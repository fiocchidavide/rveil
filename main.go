// Command rveil keeps encrypted, padded archives on an rclone remote.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"davidefiocchi.com/rveil/internal/keystore"
	"davidefiocchi.com/rveil/internal/remote"
	"davidefiocchi.com/rveil/internal/ui"
	"davidefiocchi.com/rveil/internal/vault"
	"davidefiocchi.com/rveil/internal/version"
)

func getenv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// open builds the vault from the environment.
func open() (*vault.Vault, error) {
	store, err := keystore.Open(getenv("RVEIL_KEYSTORE", "op:rveil"))
	if err != nil {
		return nil, err
	}
	return &vault.Vault{
		Store:   store,
		Remote:  remote.Rclone{Base: getenv("RVEIL_REMOTE", "rveil:rveil")},
		Staging: staging(),
		Out:     os.Stdout,
		JSON:    jsonOut,
	}, nil
}

func staging() string {
	home, _ := os.UserHomeDir()
	return getenv("RVEIL_STAGING", filepath.Join(home, ".local", "share", "rveil", "staging"))
}

// jsonOut is --json, on the commands that print data.
var jsonOut bool

func addJSON(cmds ...*cobra.Command) {
	for _, c := range cmds {
		c.Flags().BoolVar(&jsonOut, "json", false, "data as JSON lines")
	}
}

// Logging flags, as rclone has them.
var (
	verbose int
	quiet   bool
	jsonLog bool
)

func setupLog(cmd *cobra.Command, args []string) {
	level := ui.LevelNotice
	switch {
	case quiet:
		level = ui.LevelError
	case verbose == 1:
		level = ui.LevelInfo
	case verbose >= 2:
		level = ui.LevelDebug
	}
	ui.Setup(os.Stderr, slog.Level(level), jsonLog)
	trace := func(name string, args ...string) {
		ui.Debug("Running "+name+" "+strings.Join(args, " "), "event", "exec", "command", name, "args", args)
	}
	remote.Trace, keystore.Trace = trace, trace
	ui.Debug(fmt.Sprintf("rveil %s: %s", version.Version, cmd.CommandPath()), "event", "run",
		"version", version.Version, "command", cmd.CommandPath(), "args", args)
}

// Completion stays offline: archive names would need the key store and the
// remote on every Tab, so matches complete nothing, except push's, which
// come from staging.
var noFiles = cobra.NoFileCompletions

func stagedNames(_ *cobra.Command, _ []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return (&vault.Vault{Staging: staging()}).StagedNames(), cobra.ShellCompDirectiveNoFileComp
}

func ageFiles(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []cobra.Completion{"age"}, cobra.ShellCompDirectiveFilterFileExt
}

// run wraps a command body that needs the vault.
func run(f func(v *vault.Vault, args []string) error) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, args []string) error {
		v, err := open()
		if err != nil {
			return err
		}
		return f(v, args)
	}
}

func main() {
	root := &cobra.Command{
		Use:   "rveil",
		Short: "Encrypted, padded archives on an rclone remote",
		Long: `rveil keeps encrypted, padded archives of files and folders on an rclone
remote (Google Drive, a local folder, any remote that reports SHA-256),
with an encrypted index of them and master keys in 1Password.

Environment:
  RVEIL_KEYSTORE  op:<1Password vault> (default op:rveil) or file:<path>
  RVEIL_REMOTE    rclone path of the archive folder (default rveil:rveil)
  RVEIL_STAGING   staging folder for put (default ~/.local/share/rveil/staging)`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.CountVarP(&verbose, "verbose", "v", "log each step (-vv: and every event, and the commands run)")
	pf.BoolVarP(&quiet, "quiet", "q", false, "log errors only")
	pf.BoolVar(&jsonLog, "use-json-log", false, "log as JSON lines, with fields for programs")
	pf.DurationVar(&ui.Stats, "stats", 5*time.Second, "how often transfers log their progress (with -v)")
	root.PersistentPreRun = setupLog

	var direct bool
	put := &cobra.Command{
		Use:   "put [--direct] <path>...",
		Short: "Seal files or folders into staging (--direct: straight to the remote)",
		Long: `Seal each path into staging, ready for rveil push, or with --direct stream
it straight to the remote. A path that is a symlink is followed. Originals
are never touched. Prints each new archive's id (--json: its record).`,
		Args: cobra.MinimumNArgs(1),
		RunE: run(func(v *vault.Vault, args []string) error { return v.Put(args, direct) }),
	}
	put.Flags().BoolVar(&direct, "direct", false, "upload while sealing, without staging")

	push := &cobra.Command{
		Use:               "push [match...]",
		Short:             "Upload staged archives (all, or those matching) and clear them from staging",
		ValidArgsFunction: stagedNames,
		RunE:              run(func(v *vault.Vault, args []string) error { return v.Push(args) }),
	}

	var long bool
	ls := &cobra.Command{
		Use:               "ls [match]",
		Short:             "List archives: date, key, size, name (-l: with ids)",
		ValidArgsFunction: noFiles,
		Args:              cobra.MaximumNArgs(1),
		RunE: run(func(v *vault.Vault, args []string) error {
			m := ""
			if len(args) == 1 {
				m = args[0]
			}
			return v.Ls(m, long)
		}),
	}
	ls.Flags().BoolVarP(&long, "long", "l", false, "show archive ids")

	var getDir string
	get := &cobra.Command{
		Use:   "get [-C dir] <match>",
		Short: "Download an archive and extract it (into the current folder)",
		Long: `Download one archive, verify it and extract it. Nothing is overwritten:
if the name is taken, it goes into <name>.unsealed.

A match is an archive id or a part of the name (case doesn't matter).`,
		ValidArgsFunction: noFiles,
		Args:              cobra.ExactArgs(1),
		RunE:              run(func(v *vault.Vault, args []string) error { return v.Get(args[0], getDir) }),
	}
	get.Flags().StringVarP(&getDir, "dir", "C", ".", "extract into this folder")
	get.MarkFlagDirname("dir")

	var keyIndex bool
	key := &cobra.Command{
		Use:   "key <match|id> | --index",
		Short: "Print an archive's passphrase (--index: the index's, one per key)",
		Long: `Print one archive's passphrase, for stock tools:
  age -d <id>.age | zstd -d | tar x
The passphrase opens that archive only.`,
		ValidArgsFunction: noFiles,
		RunE: run(func(v *vault.Vault, args []string) error {
			if keyIndex != (len(args) == 0) || len(args) > 1 {
				return errors.New("give an archive (a match or id), or --index")
			}
			a := ""
			if len(args) == 1 {
				a = args[0]
			}
			return v.Key(a, keyIndex)
		}),
	}
	key.Flags().BoolVar(&keyIndex, "index", false, "the index's passphrase under each key")

	keys := &cobra.Command{
		Use:   "keys",
		Short: "List master keys, newest (current) first",
		Args:  cobra.NoArgs,
		RunE:  run(func(v *vault.Vault, _ []string) error { return v.KeysList() }),
	}
	keys.AddCommand(&cobra.Command{
		Use:   "new",
		Short: "Create a master key; it becomes the current one",
		Long: `Create a master key in the key store (and the 1Password vault, if missing).
New archives and the index use it from now on. To retire an older key,
move its archives with: rveil rekey --from <key>`,
		Args: cobra.NoArgs,
		RunE: run(func(v *vault.Vault, _ []string) error { return v.KeysNew() }),
	})

	var from string
	var yes bool
	rekey := &cobra.Command{
		Use:   "rekey [-y] --from <key> | <match>...",
		Short: "Re-encrypt archives under the current key, remote to remote",
		Long: `Re-encrypt archives under the current key: every archive under --from <key>,
and those matching the arguments. Only the encryption is redone; the content
isn't recompressed and never touches the disk. Each new archive is verified
before the index switches to it and the old one is deleted. A rekeyed
archive gets a new id, so links and passphrases shared for it stop working.`,
		ValidArgsFunction: noFiles,
		RunE: run(func(v *vault.Vault, args []string) error {
			if from == "" && len(args) == 0 {
				return errors.New("say which archives: --from <key>, or matches")
			}
			return v.Rekey(from, args, yes)
		}),
	}
	rekey.Flags().StringVar(&from, "from", "", "every archive under this key")
	rekey.RegisterFlagCompletionFunc("from", noFiles)
	rekey.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask")

	var rmYes bool
	rm := &cobra.Command{
		Use:               "rm [-y] <match>...",
		Short:             "Delete archives from the index, then from the remote",
		ValidArgsFunction: noFiles,
		Args:              cobra.MinimumNArgs(1),
		RunE:              run(func(v *vault.Vault, args []string) error { return v.Rm(args, rmYes) }),
	}
	rm.Flags().BoolVarP(&rmYes, "yes", "y", false, "don't ask")

	var deep, checkYes bool
	check := &cobra.Command{
		Use:   "check [--deep] [-y]",
		Short: "Compare the index with the remote and offer to fix what's off",
		Long: `Check that every archive in the index is on the remote with its recorded
hash. Offers to delete unfinished uploads and to re-add orphans (archives on
the remote but not in the index), which are read to recover their name and
hashes. --deep also downloads and decrypts every archive.`,
		Args: cobra.NoArgs,
		RunE: run(func(v *vault.Vault, _ []string) error { return v.Check(deep, checkYes) }),
	}
	check.Flags().BoolVar(&deep, "deep", false, "download and decrypt every archive")
	check.Flags().BoolVarP(&checkYes, "yes", "y", false, "fix without asking")

	share := &cobra.Command{
		Use:   "share <match>",
		Short: "Make a public link to an archive and print a message for the recipient",
		Long: `Make an anyone-with-the-link URL for an archive in the vault and print a
message with it, the archive's passphrase (which opens nothing else) and a
command that opens it on a Mac or Linux machine. rveil rm deletes the archive
and the link; rveil rekey cuts the passphrase off.`,
		ValidArgsFunction: noFiles,
		Args:              cobra.ExactArgs(1),
		RunE:              run(func(v *vault.Vault, args []string) error { return v.Share(args[0]) }),
	}

	var sealOut string
	sealCmd := &cobra.Command{
		Use:   "seal [-o out] <path>",
		Short: "Write a local archive under the current key (not indexed)",
		Args:  cobra.ExactArgs(1),
		RunE:  run(func(v *vault.Vault, args []string) error { return v.Seal(args[0], sealOut) }),
	}
	sealCmd.Flags().StringVarP(&sealOut, "out", "o", "", "output file or folder (default ./<id>.age)")

	var openDir, openKey string
	openCmd := &cobra.Command{
		Use:   "open [-C dir] [-k -] <file.age>",
		Short: "Extract a local archive",
		Long: `Extract a local archive. Its passphrase is derived from the archive id in
the file name, or read from stdin with -k -. Nothing is overwritten: if the
name is taken, it goes into <name>.unsealed.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: ageFiles,
		RunE: run(func(v *vault.Vault, args []string) error {
			if openKey != "" && openKey != "-" {
				return errors.New("-k only takes - (the passphrase on stdin), never the passphrase itself")
			}
			if openKey == "-" {
				return v.Open(args[0], openDir, os.Stdin)
			}
			return v.Open(args[0], openDir, nil)
		}),
	}
	openCmd.Flags().StringVarP(&openDir, "dir", "C", ".", "extract into this folder")
	openCmd.Flags().StringVarP(&openKey, "key", "k", "", "- to read the archive's passphrase from stdin")
	openCmd.MarkFlagDirname("dir")
	openCmd.RegisterFlagCompletionFunc("key", cobra.FixedCompletions([]cobra.Completion{"-"}, cobra.ShellCompDirectiveNoFileComp))

	addJSON(put, push, ls, keys)
	root.AddCommand(put, push, ls, get, key, keys, rekey, rm, check, share, sealCmd, openCmd)

	if err := root.Execute(); err != nil {
		if !vault.IsQuiet(err) {
			ui.Error(err.Error(), "event", "fatal", "error", err.Error())
		}
		os.Exit(1)
	}
}
