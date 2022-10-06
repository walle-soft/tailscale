// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/blake2s"
)

// randHash derives a fake blake2s hash from the test name
// and the given seed.
func randHash(t *testing.T, seed int64) [blake2s.Size]byte {
	var out [blake2s.Size]byte
	testingRand(t, seed).Read(out[:])
	return out
}

func TestImplementsChonk(t *testing.T) {
	impls := []Chonk{&Mem{}, &FS{}}
	t.Logf("chonks: %v", impls)
}

func TestTailchonk_ChildAUMs(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {
		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
			parentHash := randHash(t, 1)
			data := []AUM{
				{
					MessageKind: AUMRemoveKey,
					KeyID:       []byte{1, 2},
					PrevAUMHash: parentHash[:],
				},
				{
					MessageKind: AUMRemoveKey,
					KeyID:       []byte{3, 4},
					PrevAUMHash: parentHash[:],
				},
			}

			if err := chonk.CommitVerifiedAUMs(data); err != nil {
				t.Fatalf("CommitVerifiedAUMs failed: %v", err)
			}
			stored, err := chonk.ChildAUMs(parentHash)
			if err != nil {
				t.Fatalf("ChildAUMs failed: %v", err)
			}
			if diff := cmp.Diff(data, stored); diff != "" {
				t.Errorf("stored AUM differs (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestTailchonk_AUMMissing(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {
		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
			var notExists AUMHash
			notExists[:][0] = 42
			if _, err := chonk.AUM(notExists); err != os.ErrNotExist {
				t.Errorf("chonk.AUM(notExists).err = %v, want %v", err, os.ErrNotExist)
			}
		})
	}
}

func TestTailchonkMem_Orphans(t *testing.T) {
	chonk := Mem{}

	parentHash := randHash(t, 1)
	orphan := AUM{MessageKind: AUMNoOp}
	aums := []AUM{
		orphan,
		// A parent is specified, so we shouldnt see it in GetOrphans()
		{
			MessageKind: AUMRemoveKey,
			KeyID:       []byte{3, 4},
			PrevAUMHash: parentHash[:],
		},
	}
	if err := chonk.CommitVerifiedAUMs(aums); err != nil {
		t.Fatalf("CommitVerifiedAUMs failed: %v", err)
	}

	stored, err := chonk.Orphans()
	if err != nil {
		t.Fatalf("Orphans failed: %v", err)
	}
	if diff := cmp.Diff([]AUM{orphan}, stored); diff != "" {
		t.Errorf("stored AUM differs (-want, +got):\n%s", diff)
	}
}

func TestTailchonk_ReadChainFromHead(t *testing.T) {
	for _, chonk := range []Chonk{&Mem{}, &FS{base: t.TempDir()}} {

		t.Run(fmt.Sprintf("%T", chonk), func(t *testing.T) {
			genesis := AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}}
			gHash := genesis.Hash()
			intermediate := AUM{PrevAUMHash: gHash[:]}
			iHash := intermediate.Hash()
			leaf := AUM{PrevAUMHash: iHash[:]}

			commitSet := []AUM{
				genesis,
				intermediate,
				leaf,
			}
			if err := chonk.CommitVerifiedAUMs(commitSet); err != nil {
				t.Fatalf("CommitVerifiedAUMs failed: %v", err)
			}
			// t.Logf("genesis hash = %X", genesis.Hash())
			// t.Logf("intermediate hash = %X", intermediate.Hash())
			// t.Logf("leaf hash = %X", leaf.Hash())

			// Read the chain from the leaf backwards.
			gotLeafs, err := chonk.Heads()
			if err != nil {
				t.Fatalf("Heads failed: %v", err)
			}
			if diff := cmp.Diff([]AUM{leaf}, gotLeafs); diff != "" {
				t.Fatalf("leaf AUM differs (-want, +got):\n%s", diff)
			}

			parent, _ := gotLeafs[0].Parent()
			gotIntermediate, err := chonk.AUM(parent)
			if err != nil {
				t.Fatalf("AUM(<intermediate>) failed: %v", err)
			}
			if diff := cmp.Diff(intermediate, gotIntermediate); diff != "" {
				t.Errorf("intermediate AUM differs (-want, +got):\n%s", diff)
			}

			parent, _ = gotIntermediate.Parent()
			gotGenesis, err := chonk.AUM(parent)
			if err != nil {
				t.Fatalf("AUM(<genesis>) failed: %v", err)
			}
			if diff := cmp.Diff(genesis, gotGenesis); diff != "" {
				t.Errorf("genesis AUM differs (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestTailchonkFS_Commit(t *testing.T) {
	chonk := &FS{base: t.TempDir()}
	parentHash := randHash(t, 1)
	aum := AUM{MessageKind: AUMNoOp, PrevAUMHash: parentHash[:]}

	if err := chonk.CommitVerifiedAUMs([]AUM{aum}); err != nil {
		t.Fatal(err)
	}

	dir, base := chonk.aumDir(aum.Hash())
	if got, want := dir, filepath.Join(chonk.base, "PD"); got != want {
		t.Errorf("aum dir=%s, want %s", got, want)
	}
	if want := "PD57DVP6GKC76OOZMXFFZUSOEFQXOLAVT7N2ZM5KB3HDIMCANF4A"; base != want {
		t.Errorf("aum base=%s, want %s", base, want)
	}
	if _, err := os.Stat(filepath.Join(dir, base)); err != nil {
		t.Errorf("stat of AUM file failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(chonk.base, "M7", "M7LL2NDB4NKCZIUPVS6RDM2GUOIMW6EEAFVBWMVCPUANQJPHT3SQ")); err != nil {
		t.Errorf("stat of AUM parent failed: %v", err)
	}
}

func TestMarkActiveChain(t *testing.T) {
	type aumTemplate struct {
		AUM AUM
	}

	tcs := []struct {
		name                string
		minChain            int
		chain               []aumTemplate
		expectLastActiveIdx int // expected lastActiveAncestor, corresponds to an index on chain.
	}{
		{
			name:     "genesis",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 0,
		},
		{
			name:     "simple truncate",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 1,
		},
		{
			name:     "long truncate",
			minChain: 5,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 2,
		},
		{
			name:     "truncate finding checkpoint",
			minChain: 2,
			chain: []aumTemplate{
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMAddKey, Key: &Key{}}}, // Should keep searching upwards for a checkpoint
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
				{AUM: AUM{MessageKind: AUMCheckpoint, State: &State{}}},
			},
			expectLastActiveIdx: 1,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			verdict := make(map[AUMHash]retainState, len(tc.chain))

			// Build the state of the tailchonk for tests.
			storage := &Mem{}
			var prev AUMHash
			for i := range tc.chain {
				if !prev.IsZero() {
					tc.chain[i].AUM.PrevAUMHash = make([]byte, len(prev[:]))
					copy(tc.chain[i].AUM.PrevAUMHash, prev[:])
				}
				if err := storage.CommitVerifiedAUMs([]AUM{tc.chain[i].AUM}); err != nil {
					t.Fatal(err)
				}

				h := tc.chain[i].AUM.Hash()
				prev = h
				verdict[h] = 0
			}

			got, err := markActiveChain(storage, verdict, tc.minChain, prev)
			if err != nil {
				t.Logf("state = %+v", verdict)
				t.Fatalf("markActiveChain() failed: %v", err)
			}
			want := tc.chain[tc.expectLastActiveIdx].AUM.Hash()
			if got != want {
				t.Logf("state = %+v", verdict)
				t.Errorf("lastActiveAncestor = %v, want %v", got, want)
			}

			// Make sure the verdict array was marked correctly.
			for i := range tc.chain {
				h := tc.chain[i].AUM.Hash()
				if i >= tc.expectLastActiveIdx {
					if verdict[h] != retainStateActive {
						t.Errorf("verdict[%v] = %v, want %v", h, verdict[h], retainStateActive)
					}
				} else {
					if verdict[h] != 0 {
						t.Errorf("verdict[%v] = %v, want %v", h, verdict[h], 0)
					}
				}
			}
		})
	}
}

func TestMarkDescendantAUMs(t *testing.T) {
	c := newTestchain(t, `
        genesis -> B -> C -> C2
                   | -> D
                   | -> E -> F -> G -> H
                        | -> E2

        // tweak seeds so hashes arent identical
        C.hashSeed = 1
        D.hashSeed = 2
        E.hashSeed = 3
        E2.hashSeed = 4
    `)

	verdict := make(map[AUMHash]retainState, len(c.AUMs))
	for _, a := range c.AUMs {
		verdict[a.Hash()] = 0
	}

	// Mark E & C.
	verdict[c.AUMHashes["C"]] = retainStateActive
	verdict[c.AUMHashes["E"]] = retainStateActive

	if err := markDescendantAUMs(c.Chonk(), verdict); err != nil {
		t.Errorf("markDescendantAUMs() failed: %v", err)
	}

	// Make sure the descendants got marked.
	hs := c.AUMHashes
	for _, h := range []AUMHash{hs["C2"], hs["F"], hs["G"], hs["H"], hs["E2"]} {
		if (verdict[h] & retainStateLeaf) == 0 {
			t.Errorf("%v was not marked as a descendant", h)
		}
	}
	for _, h := range []AUMHash{hs["genesis"], hs["B"], hs["D"]} {
		if (verdict[h] & retainStateLeaf) != 0 {
			t.Errorf("%v was marked as a descendant and shouldnt be", h)
		}
	}
}

type compactingChonkFake struct {
	Mem

	aumAge     map[AUMHash]time.Time
	t          *testing.T
	wantDelete []AUMHash
}

func (c *compactingChonkFake) AllAUMs() ([]AUMHash, error) {
	out := make([]AUMHash, 0, len(c.Mem.aums))
	for h, _ := range c.Mem.aums {
		out = append(out, h)
	}
	return out, nil
}

func (c *compactingChonkFake) CommitTime(hash AUMHash) (time.Time, error) {
	return c.aumAge[hash], nil
}

func (c *compactingChonkFake) PurgeAUMs(hashes []AUMHash) error {
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i][:], hashes[j][:]) < 0
	})
	if diff := cmp.Diff(c.wantDelete, hashes); diff != "" {
		c.t.Errorf("deletion set differs (-want, +got):\n%s", diff)
	}
	return nil
}

func TestCompact(t *testing.T) {
	fakeState := &State{
		Keys:               []Key{{Kind: Key25519, Votes: 1}},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{1}, 32)},
	}

	c := newTestchain(t, `
        A -> B -> C -> D -> E -> F -> G -> H
                  | -> F1 -> F2       | -> G2
                  | -> OLD

        // make A through D compaction candidates
        A.template = checkpoint
        B.template = checkpoint
        C.template = checkpoint
        D.template = checkpoint

        // tweak seeds so hashes arent identical
        F1.hashSeed = 1
        OLD.hashSeed = 2
        G2.hashSeed = 3
    `, optTemplate("checkpoint", AUM{MessageKind: AUMCheckpoint, State: fakeState}))

	storage := &compactingChonkFake{
		Mem:        (*c.Chonk().(*Mem)),
		aumAge:     map[AUMHash]time.Time{(c.AUMHashes["F1"]): time.Now()},
		t:          t,
		wantDelete: []AUMHash{c.AUMHashes["B"], c.AUMHashes["OLD"], c.AUMHashes["C"], c.AUMHashes["A"]},
	}

	lastActiveAncestor, err := Compact(storage, c.AUMHashes["H"], CompactionOptions{MinChain: 2, MinAge: time.Hour})
	if err != nil {
		t.Errorf("Compact() failed: %v", err)
	}
	if lastActiveAncestor != c.AUMHashes["D"] {
		t.Errorf("last active ancestor = %v, want %v", lastActiveAncestor, c.AUMHashes["D"])
	}
}
