// Command models validates the model image specifications and publishes the
// images: one cosign-signed OCI modelcar per curated Hugging Face checkpoint.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/giantswarm/models/internal/hub"
	"github.com/giantswarm/models/internal/modelcar"
	"github.com/giantswarm/models/internal/sbom"
	"github.com/giantswarm/models/internal/spec"
)

const (
	source      = "https://github.com/giantswarm/models"
	usernameEnv = "MODELS_REGISTRY_USERNAME"
	passwordEnv = "MODELS_REGISTRY_PASSWORD"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "models",
		Short:         "Curated model images: Hugging Face checkpoints as signed OCI modelcars",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(validateCommand(), publishCommand())
	return cmd
}

func validateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [dir]",
		Short: "Check every specification and resolve its checkpoint on the Hub",
		Long: `validate reads every specification under the directory (models/ by default),
checks its fields, and asks the Hub for the revision's file list. It prints
what an image built from each specification would hold.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "models"
			if len(args) == 1 {
				dir = args[0]
			}
			specs, err := spec.LoadDir(dir)
			if err != nil {
				return err
			}
			client := hub.New(userAgent())
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "IMAGE\tTAG\tCHECKPOINT\tFILES\tSIZE")
			var failed bool
			for _, m := range specs {
				files, size, err := resolve(cmd.Context(), client, m)
				if err != nil {
					failed = true
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t-\t%v\n", m.Metadata.Name, m.Tag(), m.Spec.HuggingFace.Repository, err)
					continue
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s@%s\t%d\t%s\n", m.Metadata.Name, m.Tag(), m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision[:12], files, gib(size))
			}
			_ = w.Flush()
			if failed {
				return errors.New("a specification does not resolve")
			}
			return nil
		},
	}
}

func resolve(ctx context.Context, client *hub.Client, m *spec.ModelImage) (int, int64, error) {
	if _, err := client.Revision(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision); err != nil {
		return 0, 0, err
	}
	tree, err := client.Tree(ctx, m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
	if err != nil {
		return 0, 0, err
	}
	var n int
	var size int64
	for _, f := range tree {
		if !m.Excluded(f.Path) {
			n++
			size += f.Size
		}
	}
	return n, size, nil
}

func gib(n int64) string {
	return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
}

type publishFlags struct {
	dir        string
	specFile   string
	registry   string
	refsFile   string
	attestFile string
	sbomDir    string
	chunkMiB   int
	interval   time.Duration
}

func publishCommand() *cobra.Command {
	var f publishFlags
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Build and push every image the registry does not hold yet",
		Long: `publish builds the image of each specification whose tag is missing from the
registry and pushes it: the weights stream from the Hub through one
uncompressed tar layer into the registry, never onto local disk. A tag that
already holds the specification's checkpoint is left alone; one that holds
another checkpoint fails the run.

Credentials come from ` + usernameEnv + ` and ` + passwordEnv + `, or from the
Docker credential store when they are unset.

For the signing steps that follow, publish appends every image's digest
reference to --refs-file and, with an SPDX document per image written to
--sbom-dir, a "<ref> spdxjson <file>" line to --attest-file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return publish(cmd.Context(), f, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&f.dir, "dir", "models", "directory of the specifications")
	cmd.Flags().StringVar(&f.specFile, "spec", "", "publish this one specification file instead of the directory")
	cmd.Flags().StringVar(&f.registry, "registry", "gsoci.azurecr.io/giantswarm/models", "repository prefix the images are pushed under")
	cmd.Flags().StringVar(&f.refsFile, "refs-file", "", "append each published image's digest reference to this file (for cosign sign)")
	cmd.Flags().StringVar(&f.attestFile, "attest-file", "", "append '<ref> spdxjson <sbom>' per image to this file (for cosign attest)")
	cmd.Flags().StringVar(&f.sbomDir, "sbom-dir", "", "write one SPDX document per image into this directory")
	cmd.Flags().IntVar(&f.chunkMiB, "chunk-mib", 256, "size of one blob upload request in MiB")
	cmd.Flags().DurationVar(&f.interval, "progress-interval", 30*time.Second, "how often the transfer is logged")
	return cmd
}

func publish(ctx context.Context, f publishFlags, out io.Writer) error {
	var specs []*spec.ModelImage
	if f.specFile != "" {
		m, err := spec.Load(f.specFile)
		if err != nil {
			return err
		}
		specs = []*spec.ModelImage{m}
	} else {
		var err error
		if specs, err = spec.LoadDir(f.dir); err != nil {
			return err
		}
	}
	registry, err := name.NewRepository(f.registry)
	if err != nil {
		return fmt.Errorf("--registry: %w", err)
	}
	auth, err := authenticator(registry)
	if err != nil {
		return err
	}
	if f.sbomDir != "" {
		if err := os.MkdirAll(f.sbomDir, 0o750); err != nil {
			return err
		}
	}
	logger := log.New(out, "", log.LstdFlags|log.LUTC)
	tool := userAgent()
	opts := modelcar.Options{
		Registry: registry, Hub: hub.New(tool), Auth: auth, Source: source, Tool: tool,
		ChunkSize: f.chunkMiB << 20, ProgressInterval: f.interval, Log: logger.Printf,
	}
	for _, m := range specs {
		logger.Printf("%s: %s", m.Path, m.Metadata.Name)
		p, err := modelcar.Publish(ctx, m, opts)
		if err != nil {
			return fmt.Errorf("%s: %w", m.Path, err)
		}
		ref := fmt.Sprintf("%s@%s", p.Reference.Context(), p.Digest)
		if err := appendLine(f.refsFile, ref); err != nil {
			return err
		}
		if f.sbomDir != "" && f.attestFile != "" {
			if p.Existed {
				logger.Printf("%s: the image existed before this run; its SBOM was attested when it was built", m.Metadata.Name)
				continue
			}
			doc, err := sbom.Build(m, p, tool, time.Now()).JSON()
			if err != nil {
				return err
			}
			file := filepath.Join(f.sbomDir, fmt.Sprintf("%s-%s.spdx.json", m.Metadata.Name, m.Tag()))
			if err := os.WriteFile(file, doc, 0o600); err != nil {
				return err
			}
			if err := appendLine(f.attestFile, fmt.Sprintf("%s spdxjson %s", ref, file)); err != nil {
				return err
			}
		}
	}
	return nil
}

// authenticator signs in with the environment's credentials, else with the
// Docker credential store of the machine.
func authenticator(repo name.Repository) (authn.Authenticator, error) {
	user, pass := os.Getenv(usernameEnv), os.Getenv(passwordEnv)
	switch {
	case user != "" && pass != "":
		return &authn.Basic{Username: user, Password: pass}, nil
	case user != "" || pass != "":
		return nil, fmt.Errorf("set both %s and %s, or neither", usernameEnv, passwordEnv)
	}
	return authn.DefaultKeychain.Resolve(repo.Registry)
}

func appendLine(file, line string) error {
	if file == "" {
		return nil
	}
	fh, err := os.OpenFile(filepath.Clean(file), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(fh, line); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

// userAgent names the tool and its version to the Hub and the registry.
func userAgent() string {
	version := "dev"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	return "giantswarm-models/" + strings.TrimPrefix(version, "v")
}
