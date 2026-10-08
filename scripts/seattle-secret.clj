#!/usr/bin/env bb
;;
;; seattle-secret -- create and update SOPS-encrypted Kubernetes Secrets
;; for the Seattle cluster.
;;
;; Encrypted manifests live in ./secrets and are decrypted in-cluster by
;; Flux's kustomize-controller. Recipients come from ./.sops.yaml.
;;
;; Secret values are held in memory and handed to sops on stdin; nothing is
;; written to disk until sops has returned the ciphertext.

(require '[babashka.fs :as fs]
         '[babashka.process :as process]
         '[clj-yaml.core :as yaml]
         '[clojure.string :as str]
         '[flatland.ordered.map :refer [ordered-map]])

(def prog "seattle-secret")

(defn die [& parts]
  (binding [*out* *err*] (println (str prog ": " (apply str parts))))
  (System/exit 1))

(defn note [& parts]
  (binding [*out* *err*] (println (apply str parts))))

(defn usage []
  (println (str "Usage: " prog " <command> [options] [<secret-name>]

Commands:
  add <name>     Create a new encrypted Secret in ./secrets
  set <name>     Add or replace keys in an existing Secret
  import <file>  Encrypt a complete plaintext Secret manifest into ./secrets
  show <name>    Decrypt a Secret and print it
  edit <name>    Open a Secret in $EDITOR, re-encrypting on save
  list           List the Secrets in this repository
  check          Verify that the repository is internally consistent

Value options (repeatable; valid for 'add' and 'set'):
  --password[=KEY]      Prompt for a value, with confirmation (default key: password)
  --token[=KEY]         Prompt for a value, once (default key: token)
  --file [KEY=]PATH     Read a file; KEY defaults to its basename
  --literal KEY=VALUE   Take the value from the command line

Options for 'add':
  -n, --namespace NS    Kubernetes namespace (required)
  -o, --output NAME     Filename under ./secrets (default: <name>.yaml)
  --secret-type TYPE    Kubernetes Secret type (default: Opaque)

Options for 'import':
  -o, --output NAME     Filename under ./secrets (default: <metadata.name>.yaml)
  --force               Replace an existing file in ./secrets
  <file> may be '-' to read the manifest from stdin.

'set', 'show' and 'edit' decrypt the existing file, so they need the private
key (SOPS_AGE_KEY_FILE). 'add' and 'import' only encrypt and work without it.

Prompted values are read from the terminal and never appear in your shell
history. Files are base64-encoded into 'data'; every other value goes into
'stringData' verbatim, so no manual encoding is needed either way.

Examples:
  " prog " add --namespace klaxon --file=/tmp/key-file.json klaxon-key-file
  " prog " add -n hermes --password --token=api-key hermes-secrets
  " prog " set hermes-secrets --literal RCON_PASSWORD=swordfish
  " prog " set hermes-secrets --file=id_ed25519 --file=krb5.keytab
  " prog " import /tmp/teslamate-secrets.yaml --force")))

;; --- repository layout -------------------------------------------------------

(defn find-root []
  (let [root (or (not-empty (or (System/getenv "SEATTLE_SECRETS_DIR") ""))
                 (let [{:keys [exit out]} (process/shell
                                           {:out :string :err :string :continue true}
                                           "git" "rev-parse" "--show-toplevel")]
                   (when (zero? exit) (str/trim out))))]
    (when-not root
      (die "not inside the secrets repository (set SEATTLE_SECRETS_DIR to override)"))
    (when-not (fs/regular-file? (fs/path root ".sops.yaml"))
      (die "no .sops.yaml in " root " -- is this the secrets repository?"))
    root))

(defn resolve-secret [root nm]
  (or (some (fn [rel] (when (fs/regular-file? (fs/path root rel)) rel))
            [(str "secrets/" nm) (str "secrets/" nm ".yaml") (str "secrets/" nm ".enc.yaml")])
      (die "no such secret: " nm " (looked in " root "/secrets)")))

;; --- sops --------------------------------------------------------------------

(defn sops-encrypt
  "Encrypt yaml-str as though it were the file at rel, returning the ciphertext.
   The path drives which .sops.yaml creation rule applies, so it matters even
   though sops is reading from stdin."
  [root rel yaml-str]
  (let [{:keys [exit out err]} (process/shell
                                {:dir root :in yaml-str :out :string :err :string :continue true}
                                "sops" "encrypt" "--filename-override" rel)]
    (when-not (zero? exit)
      (die "sops encrypt failed: " (str/trim (str err))))
    out))

(defn sops-decrypt [root rel]
  (let [{:keys [exit out err]} (process/shell
                                {:dir root :out :string :err :string :continue true}
                                "sops" "decrypt" rel)]
    (when-not (zero? exit)
      (die "sops decrypt failed: " (str/trim (str err))))
    out))

;; --- values ------------------------------------------------------------------
;;
;; Each value is an entry {:field "data"|"stringData" :key k :value v}. A
;; prompted entry carries {:prompt {:confirm? bool}} instead of :value until
;; resolve-entries fills it in -- that happens only after every other argument
;; has been validated, so a typo never costs you a re-typed password.

(defn valid-name? [s]
  (boolean (and (string? s) (re-matches #"[A-Za-z0-9._-]+" s))))

(defn file->entry [spec]
  (let [i (str/index-of spec "=")
        [k path] (if i
                   [(subs spec 0 i) (subs spec (inc i))]
                   [(str (fs/file-name spec)) spec])]
    (when (str/blank? path) (die "--file needs a path"))
    (when-not (fs/regular-file? path) (die "no such file: " path))
    (when-not (fs/readable? path) (die "cannot read file: " path))
    {:field "data"
     :key k
     :value (.encodeToString (java.util.Base64/getEncoder) (fs/read-all-bytes path))}))

(defn literal->entry [spec]
  (if-let [i (str/index-of spec "=")]
    {:field "stringData" :key (subs spec 0 i) :value (subs spec (inc i))}
    (die "--literal needs KEY=VALUE, got '" spec "'")))

(defn parse-value-arg
  "Return [entry args-consumed] when a is a value option, else nil.

   The prompting options name their key with '=' only, so that a bare
   '--password' can never swallow the secret name that follows it."
  [a b]
  (cond
    (= a "--file")                     [(file->entry (or b (die "--file needs a path"))) 2]
    (str/starts-with? a "--file=")     [(file->entry (subs a 7)) 1]
    (= a "--literal")                  [(literal->entry (or b (die "--literal needs KEY=VALUE"))) 2]
    (str/starts-with? a "--literal=")  [(literal->entry (subs a 10)) 1]
    (= a "--password")                 [{:field "stringData" :key "password" :prompt {:confirm? true}} 1]
    (str/starts-with? a "--password=") [{:field "stringData" :key (subs a 11) :prompt {:confirm? true}} 1]
    (= a "--token")                    [{:field "stringData" :key "token" :prompt {:confirm? false}} 1]
    (str/starts-with? a "--token=")    [{:field "stringData" :key (subs a 8) :prompt {:confirm? false}} 1]
    :else nil))

(defn read-hidden
  "Read one line from the terminal without echoing it. nil on EOF."
  [console prompt]
  (binding [*out* *err*] (print prompt) (flush))
  (when-let [chars (.readPassword console)]
    (String. chars)))

(defn prompt-value [k confirm?]
  (let [console (System/console)]
    (when-not console
      (die "no terminal available to prompt for '" k "' (use --literal or --file)"))
    (loop []
      (let [v (read-hidden console (str "Value for " k ": "))]
        (when (nil? v) (die "aborted while reading '" k "'"))
        (cond
          (empty? v)
          (do (note "empty value, try again") (recur))

          confirm?
          (let [again (read-hidden console (str "Confirm " k ": "))]
            (when (nil? again) (die "aborted while reading '" k "'"))
            (if (= v again)
              v
              (do (note "values did not match, try again") (recur))))

          :else v)))))

(defn validate-entries [entries]
  (doseq [{:keys [key]} entries]
    (when-not (valid-name? key)
      (die "invalid secret key '" key "': use only letters, digits, '.', '-' and '_'")))
  (when-let [dup (->> entries (map :key) frequencies (keep (fn [[k n]] (when (> n 1) k))) first)]
    (die "key '" dup "' given twice"))
  entries)

(defn resolve-entries [entries]
  (mapv (fn [{:keys [prompt] :as e}]
          (if prompt
            (-> e (assoc :value (prompt-value (:key e) (:confirm? prompt))) (dissoc :prompt))
            e))
        entries))

(defn apply-entries [manifest entries]
  (reduce (fn [m {:keys [field key value]}]
            (assoc m field (assoc (or (get m field) (ordered-map)) key value)))
          manifest
          entries))

(defn ->yaml [m]
  (yaml/generate-string m :dumper-options {:flow-style :block}))

(defn load-manifest [path]
  (yaml/parse-string (slurp (fs/file path)) :keywords false))

(defn value-keys [m]
  (concat (keys (get m "data")) (keys (get m "stringData"))))

(defn report-keys [root rel]
  (note "  keys: " (str/join " " (value-keys (load-manifest (fs/path root rel))))))

;; --- argument parsing --------------------------------------------------------

(defn parse-args
  "Parse argv for 'add' / 'set'. extra is a map of option -> [state-key arity]
   for the options a command accepts beyond the shared value options."
  [args extra]
  (loop [args args, st {:entries []}]
    (if (empty? args)
      st
      (let [a (first args), b (second args)]
        (if-let [[entry n] (parse-value-arg a b)]
          (recur (drop n args) (update st :entries conj entry))
          (if-let [[k] (get extra a)]
            (recur (drop 2 args) (assoc st k (or b (die a " needs a value"))))
            (let [long-eq (some (fn [[opt [k]]]
                                  (when (and (str/starts-with? opt "--")
                                             (str/starts-with? a (str opt "=")))
                                    [k (subs a (inc (count opt)))]))
                                extra)]
              (cond
                long-eq              (recur (rest args) (assoc st (first long-eq) (second long-eq)))
                (#{"-h" "--help"} a) (do (usage) (System/exit 0))
                (str/starts-with? a "-") (die "unknown option: " a)
                (:secret-name st)    (die "unexpected argument: " a)
                :else                (recur (rest args) (assoc st :secret-name a))))))))))

;; --- commands ----------------------------------------------------------------

(defn cmd-add [args]
  (let [{:keys [entries secret-name secret-ns output secret-type]}
        (parse-args args {"-n"             [:secret-ns]
                          "--namespace"    [:secret-ns]
                          "-o"             [:output]
                          "--output"       [:output]
                          "--secret-type"  [:secret-type]})
        secret-type (or secret-type "Opaque")]
    (when-not secret-name (die "add: missing secret name"))
    (when-not (valid-name? secret-name) (die "invalid secret name '" secret-name "'"))
    (when-not secret-ns (die "add: --namespace is required"))
    (when-not (valid-name? secret-ns) (die "invalid namespace '" secret-ns "'"))
    (when (empty? entries)
      (die "add: no values given (use --password, --token, --file or --literal)"))
    (validate-entries entries)
    (let [root (find-root)
          rel  (str "secrets/" (or output (str secret-name ".yaml")))]
      (when (fs/exists? (fs/path root rel))
        (die rel " already exists -- use '" prog " set " secret-name "' to change it"))
      (let [manifest (apply-entries
                      (ordered-map "apiVersion" "v1"
                                   "kind" "Secret"
                                   "metadata" (ordered-map "name" secret-name
                                                           "namespace" secret-ns)
                                   "type" secret-type)
                      (resolve-entries entries))]
        (fs/create-dirs (fs/path root "secrets"))
        (spit (fs/file root rel) (sops-encrypt root rel (->yaml manifest)))
        (note "wrote " rel)
        (report-keys root rel)))))

(defn cmd-set [args]
  (let [{:keys [entries secret-name]} (parse-args args {})]
    (when-not secret-name (die "set: missing secret name"))
    (when (empty? entries) (die "set: no values given"))
    (validate-entries entries)
    (let [root (find-root)
          rel  (resolve-secret root secret-name)
          manifest (apply-entries (yaml/parse-string (sops-decrypt root rel) :keywords false)
                                  (resolve-entries entries))]
      (spit (fs/file root rel) (sops-encrypt root rel (->yaml manifest)))
      (note "updated " rel)
      (report-keys root rel))))

(defn cmd-show [args]
  (let [nm (or (first args) (die "show: missing secret name"))
        root (find-root)]
    (print (sops-decrypt root (resolve-secret root nm)))
    (flush)))

(defn cmd-edit [args]
  (let [nm (or (first args) (die "edit: missing secret name"))
        root (find-root)
        {:keys [exit]} (process/shell {:dir root :continue true}
                                      "sops" "edit" (resolve-secret root nm))]
    (System/exit exit)))

(defn secret-files [root]
  (->> (fs/glob root "secrets/*.yaml")
       (map #(str (fs/relativize root %)))
       sort))

(defn cmd-list [_]
  (let [root (find-root)]
    (doseq [rel (secret-files root)]
      (let [m (load-manifest (fs/path root rel))]
        (println (format "%-44s %-20s %s"
                         (str (fs/file-name rel))
                         (or (get-in m ["metadata" "namespace"]) "-")
                         (str/join "," (value-keys m))))))))

(defn cmd-check [_]
  (let [root (find-root)
        configured (-> (load-manifest (fs/path root ".sops.yaml"))
                       (get "creation_rules") first (get "age"))
        pubkey (str/replace (slurp (fs/file root "cluster.agekey.public")) #"\s" "")
        key-ok? (= configured pubkey)
        problems (for [rel (secret-files root)
                       :let [m (load-manifest (fs/path root rel))
                             found (cond-> []
                                     (nil? (get m "sops"))                    (conj "not-encrypted")
                                     (not= "Secret" (get m "kind"))           (conj "not-a-Secret")
                                     (str/blank? (get-in m ["metadata" "name"]))      (conj "no-name")
                                     (str/blank? (get-in m ["metadata" "namespace"])) (conj "no-namespace"))]
                       :when (seq found)]
                   (str (fs/file-name rel) ": " (str/join " " found)))]
    (if key-ok?
      (note "ok   .sops.yaml matches cluster.agekey.public")
      (note "FAIL .sops.yaml recipient does not match cluster.agekey.public"))
    (doseq [p problems] (note "FAIL " p))
    (when (and key-ok? (empty? problems))
      (note "ok   all secrets are encrypted and namespaced"))
    (System/exit (if (and key-ok? (empty? problems)) 0 1))))

;; --- import ------------------------------------------------------------------

(defn parse-import-args [args]
  (loop [args args, st {}]
    (if (empty? args)
      st
      (let [[a b] args]
        (cond
          (#{"-o" "--output"} a)           (recur (drop 2 args) (assoc st :output (or b (die a " needs a value"))))
          (str/starts-with? a "--output=") (recur (rest args) (assoc st :output (subs a 9)))
          (= a "--force")                  (recur (rest args) (assoc st :force? true))
          (#{"-h" "--help"} a)             (do (usage) (System/exit 0))
          (and (str/starts-with? a "-") (not= a "-")) (die "unknown option: " a)
          (:source st)                     (die "unexpected argument: " a)
          :else                            (recur (rest args) (assoc st :source a)))))))

(defn base64-decode [s]
  (try (.decode (java.util.Base64/getDecoder) (str/replace (str s) #"\s" ""))
       (catch IllegalArgumentException _ nil)))

(defn validate-import
  "Die unless m is a plaintext Secret this repository can hold."
  [m]
  (when-not (map? m) (die "import: not a YAML mapping"))
  (when (contains? m "sops") (die "import: already encrypted by sops"))
  (when-not (= "Secret" (get m "kind"))
    (die "import: kind is '" (get m "kind") "', expected 'Secret'"))
  (let [nm (get-in m ["metadata" "name"])
        ns (get-in m ["metadata" "namespace"])]
    (when-not (valid-name? nm) (die "import: missing or invalid metadata.name"))
    (when-not (valid-name? ns) (die "import: missing or invalid metadata.namespace")))
  (when (empty? (value-keys m)) (die "import: no data or stringData"))
  (doseq [field ["data" "stringData"]
          [k v] (get m field)]
    (when-not (valid-name? (str k))
      (die "import: invalid key '" k "' in " field))
    (when-not (string? v)
      (die "import: " field "." k " is not a string (quote it in the YAML)")))
  (doseq [[k v] (get m "data")]
    (let [bytes (or (base64-decode v) (die "import: data." k " is not valid base64"))]
      (when (and (pos? (alength bytes)) (= 10 (aget bytes (dec (alength bytes)))))
        (note "warning: data." k " ends with a newline -- was it made with 'echo | base64'?"))))
  m)

(defn cmd-import [args]
  (let [{:keys [source output force?]} (parse-import-args args)
        _ (when-not source (die "import: missing file (use '-' for stdin)"))
        text (if (= source "-")
               (slurp *in*)
               (do (when-not (fs/regular-file? source) (die "no such file: " source))
                   (slurp (fs/file source))))
        docs (try (yaml/parse-string text :keywords false :load-all true)
                  (catch Exception e (die "import: cannot parse YAML: " (ex-message e))))
        docs (remove nil? docs)
        _ (when (not= 1 (count docs))
            (die "import: expected exactly one YAML document, found " (count docs)))
        m (validate-import (first docs))
        root (find-root)
        rel (str "secrets/" (or output (str (get-in m ["metadata" "name"]) ".yaml")))
        target (fs/path root rel)
        in-place? (and (not= source "-") (fs/exists? target)
                       (= (str (fs/canonicalize source)) (str (fs/canonicalize target))))]
    (when (and (fs/exists? target) (not in-place?) (not force?))
      (die rel " already exists -- pass --force to replace it"))
    (fs/create-dirs (fs/path root "secrets"))
    ;; Re-emitting the parsed map drops comments, which sops would otherwise
    ;; carry into the committed file.
    (spit (fs/file target) (sops-encrypt root rel (->yaml m)))
    (note (if in-place? "encrypted " "wrote ") rel)
    (report-keys root rel)
    (when (and (not= source "-") (not in-place?))
      (note "the plaintext is still at " source " -- delete it once you are done"))))

;; --- entry point -------------------------------------------------------------

(let [[cmd & args] *command-line-args*]
  (case cmd
    "add"   (cmd-add args)
    "set"   (cmd-set args)
    "import" (cmd-import args)
    "show"  (cmd-show args)
    "edit"  (cmd-edit args)
    "list"  (cmd-list args)
    "check" (cmd-check args)
    ("-h" "--help" "help") (usage)
    nil (do (binding [*out* *err*] (usage)) (System/exit 2))
    (die "unknown command '" cmd "' (try '" prog " --help')")))
