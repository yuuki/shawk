package tracer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// TestKernelCompatibility checks the BPF programs against the BTF of another
// kernel without loading them: the attach targets must exist with the
// parameters the programs read, the helpers must be known and every CO-RE
// relocation must resolve.
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
	if prog.AttachType != ebpf.AttachTraceIter {
		checkPrototype(t, target, prog)
	}
}

// sourcePrototypes returns the parameters that the programs attached to
// kernel functions and BTF tracepoints read, as BPF_PROG declares them in the
// BPF source, keyed by program name. The verifier checks only the number of
// arguments of a function read through BPF_CORE_READ, so a parameter whose
// type changed would make a program read the wrong argument.
func sourcePrototypes(t *testing.T) map[string][]string {
	t.Helper()
	src, err := os.ReadFile("bpf/shawk.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`SEC\("(?:fentry|fexit|tp_btf)/\w+"\)\s*int\s+BPF_PROG\(\s*(\w+)([^)]*)\)`)
	protos := map[string][]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		params := []string{}
		for _, p := range strings.Split(m[2], ",") {
			if p = strings.TrimSpace(p); p != "" {
				params = append(params, p)
			}
		}
		protos[m[1]] = params
	}
	return protos
}

// declType names the type of a C parameter declaration like paramType names
// a BTF type, resolving typedefs in the kernel's BTF: "const struct sock *sk"
// is "*sock".
func declType(spec *btf.Spec, decl string) string {
	fields := strings.Fields(strings.ReplaceAll(decl, "*", " * "))
	fields = fields[:len(fields)-1] // the parameter name
	var (
		stars string
		words []string
	)
	for _, f := range fields {
		switch f {
		case "*":
			stars += "*"
		case "const", "volatile", "struct", "union", "enum":
		default:
			words = append(words, f)
		}
	}
	base := strings.Join(words, " ")
	var td *btf.Typedef
	if spec.TypeByName(base, &td) == nil {
		base = paramType(td)
	}
	return stars + base
}

// kernelPrototype returns the parameters of the kernel function or BTF
// tracepoint a program attaches to, without the context of a tracepoint.
func kernelPrototype(spec *btf.Spec, prog *ebpf.ProgramSpec) ([]string, error) {
	var proto *btf.FuncProto
	switch prog.AttachType {
	case ebpf.AttachTraceRawTp:
		var td *btf.Typedef
		if err := spec.TypeByName("btf_trace_"+prog.AttachTo, &td); err != nil {
			return nil, err
		}
		ptr, ok := btf.UnderlyingType(td).(*btf.Pointer)
		if !ok {
			return nil, fmt.Errorf("btf_trace_%s is not a function pointer", prog.AttachTo)
		}
		if proto, ok = ptr.Target.(*btf.FuncProto); !ok || len(proto.Params) == 0 {
			return nil, fmt.Errorf("btf_trace_%s is not a function pointer", prog.AttachTo)
		}
		proto = &btf.FuncProto{Return: proto.Return, Params: proto.Params[1:]}
	default:
		var fn *btf.Func
		if err := spec.TypeByName(prog.AttachTo, &fn); err != nil {
			return nil, err
		}
		var ok bool
		if proto, ok = fn.Type.(*btf.FuncProto); !ok {
			return nil, fmt.Errorf("%s has no prototype", prog.AttachTo)
		}
	}
	params := make([]string, 0, len(proto.Params))
	for _, p := range proto.Params {
		params = append(params, paramType(p.Type))
	}
	return params, nil
}

func checkPrototype(t *testing.T, target *btf.Spec, prog *ebpf.ProgramSpec) {
	t.Helper()
	decls, ok := sourcePrototypes(t)[prog.Name]
	if !ok {
		t.Errorf("BPF_PROG of %s not found in the source", prog.Name)
		return
	}
	got, err := kernelPrototype(target, prog)
	if err != nil {
		return // reported by checkAttachTarget
	}
	want := make([]string, 0, len(decls))
	for _, d := range decls {
		want = append(want, declType(target, d))
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("parameters of %s = %v, %s reads %v", prog.AttachTo, got, prog.Name, want)
	}
}

// paramType names a parameter type: the name of an integer, or of the
// struct a pointer points to, prefixed with *.
func paramType(typ btf.Type) string {
	typ = btf.UnderlyingType(typ)
	if ptr, ok := typ.(*btf.Pointer); ok {
		return "*" + paramType(ptr.Target)
	}
	if typ == nil {
		return "void"
	}
	return typ.TypeName()
}

// TestProgramPrototypes checks the prototypes of the kernel functions and
// BTF tracepoints the programs attach to in the running kernel, including
// those of modules (e.g. ip6_send_skb with IPv6 built as a module). It needs
// no privileges.
func TestProgramPrototypes(t *testing.T) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, prog := range spec.Programs {
		if prog.AttachType == ebpf.AttachTraceIter {
			continue
		}
		n++
		target := kernel
		if _, err := kernelPrototype(kernel, prog); errors.Is(err, btf.ErrNotFound) {
			if target = moduleSpecOf(prog); target == nil {
				skipUnavailable(t, "attach target %s is not in the kernel's BTF", prog.AttachTo)
				continue
			}
		}
		checkPrototype(t, target, prog)
	}
	if want := len(sourcePrototypes(t)); n != want {
		t.Errorf("%d programs attach to kernel functions or tracepoints, the source declares %d", n, want)
	}
}

// moduleSpecOf returns the BTF of the kernel module that holds the attach
// target of a program, or nil.
func moduleSpecOf(prog *ebpf.ProgramSpec) *btf.Spec {
	entries, _ := os.ReadDir("/sys/kernel/btf")
	for _, e := range entries {
		if e.Name() == "vmlinux" {
			continue
		}
		spec, err := btf.LoadKernelModuleSpec(e.Name())
		if err != nil {
			continue
		}
		if _, err := kernelPrototype(spec, prog); err == nil {
			return spec
		}
	}
	return nil
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
