package tracer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// TestKernelCompatibility checks the BPF programs against the BTF of another
// kernel without loading them: the attach targets must exist, the helpers
// must be known and every CO-RE relocation must resolve.
//
// Set SHAWK_TARGET_BTF to a raw BTF file or a vmlinux ELF, for example one
// extracted by scripts/fetch-kernel-btf.sh for Rocky Linux 9.
func TestKernelCompatibility(t *testing.T) {
	path := os.Getenv("SHAWK_TARGET_BTF")
	if path == "" {
		t.Skip("SHAWK_TARGET_BTF is not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	target, err := btf.LoadSpecFromReader(f)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	helpers := enumValues(t, target, "bpf_func_id")

	for name, prog := range spec.Programs {
		t.Run(name, func(t *testing.T) {
			checkAttachTarget(t, target, prog)

			var relos []*btf.CORERelocation
			for i := range prog.Instructions {
				ins := &prog.Instructions[i]
				if r := btf.CORERelocationMetadata(ins); r != nil {
					relos = append(relos, r)
				}
				if ins.IsBuiltinCall() && !helpers[uint64(ins.Constant)] {
					t.Errorf("helper %v is not available", asm.BuiltinFunc(ins.Constant))
				}
				// The arm64 JIT supports atomic operations other than a plain
				// add only since Linux 5.18.
				if op := ins.OpCode.AtomicOp(); op != asm.InvalidAtomic && op != asm.AddAtomic {
					t.Errorf("instruction %d: atomic operation %v is not supported by the arm64 JIT before Linux 5.18", i, op)
				}
			}
			fixups, err := btf.CORERelocate(relos, []*btf.Spec{target}, binary.LittleEndian, spec.Types.TypeID)
			if err != nil {
				t.Fatalf("CO-RE relocation: %v", err)
			}
			if os.Getenv("SHAWK_DEBUG_CORE") != "" {
				for i, fx := range fixups {
					t.Logf("%v => %v", relos[i], fx.String())
				}
			}
			for i, fx := range fixups {
				if strings.Contains(fx.String(), "poison") {
					t.Errorf("unresolvable CO-RE relocation %v", relos[i])
				}
			}
		})
	}
}

func checkAttachTarget(t *testing.T, target *btf.Spec, prog *ebpf.ProgramSpec) {
	t.Helper()
	var err error
	switch prog.AttachType {
	case ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit:
		var fn *btf.Func
		err = target.TypeByName(prog.AttachTo, &fn)
	case ebpf.AttachTraceRawTp:
		var td *btf.Typedef
		err = target.TypeByName("btf_trace_"+prog.AttachTo, &td)
	case ebpf.AttachTraceIter:
		var st *btf.Struct
		err = target.TypeByName("bpf_iter__"+prog.AttachTo, &st)
	default:
		t.Fatalf("unexpected attach type %v", prog.AttachType)
	}
	if errors.Is(err, btf.ErrNotFound) {
		t.Errorf("attach target %s is not available", prog.AttachTo)
	} else if err != nil {
		t.Errorf("looking up attach target %s: %v", prog.AttachTo, err)
	}
}

func enumValues(t *testing.T, spec *btf.Spec, name string) map[uint64]bool {
	t.Helper()
	var e *btf.Enum
	if err := spec.TypeByName(name, &e); err != nil {
		t.Fatalf("looking up enum %s: %v", name, err)
	}
	values := make(map[uint64]bool, len(e.Values))
	for _, v := range e.Values {
		if !strings.HasPrefix(v.Name, "__") {
			values[v.Value] = true
		}
	}
	return values
}

// TestCommittedObject checks that the BPF object embedded in the binary,
// which is committed, matches the object given by SHAWK_FRESH_OBJECT,
// compiled from the current source. The bytes of the object depend on the
// directory it was built in, so the programs and maps are compared instead.
func TestCommittedObject(t *testing.T) {
	path := os.Getenv("SHAWK_FRESH_OBJECT")
	if path == "" {
		t.Skip("SHAWK_FRESH_OBJECT is not set")
	}
	fresh, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	stale := "the committed internal/tracer/bpf_bpfel.o does not match the source; run make generate"
	if len(fresh.Programs) != len(committed.Programs) || len(fresh.Maps) != len(committed.Maps) {
		t.Fatalf("%s: programs or maps differ", stale)
	}
	for name, fp := range fresh.Programs {
		cp, ok := committed.Programs[name]
		if !ok {
			t.Fatalf("%s: program %s is missing", stale, name)
		}
		if fp.Type != cp.Type || fp.AttachType != cp.AttachType || fp.AttachTo != cp.AttachTo || fp.License != cp.License {
			t.Errorf("%s: program %s differs", stale, name)
		}
		if f, c := fmt.Sprint(fp.Instructions), fmt.Sprint(cp.Instructions); f != c {
			t.Errorf("%s: instructions of %s differ", stale, name)
		}
	}
	for name, fm := range fresh.Maps {
		cm, ok := committed.Maps[name]
		if !ok {
			t.Fatalf("%s: map %s is missing", stale, name)
		}
		if fm.Type != cm.Type || fm.KeySize != cm.KeySize || fm.ValueSize != cm.ValueSize ||
			fm.MaxEntries != cm.MaxEntries || fm.Flags != cm.Flags || fmt.Sprint(fm.Contents) != fmt.Sprint(cm.Contents) {
			t.Errorf("%s: map %s differs", stale, name)
		}
	}
}
