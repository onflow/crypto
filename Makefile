# Name of the cover profile
COVER_PROFILE := cover.out

IMAGE_TAG := v0.0.7

# OS
UNAME := $(shell uname -s)

# allows CI to specify whether to have race detection on / off
ifeq ($(RACE_DETECTOR),1)
	RACE_FLAG := -race
else
	RACE_FLAG :=
endif

# `ADX_SUPPORT` is 1 if ADX instructions are supported and 0 otherwise.
ifeq ($(UNAME),Linux)
# detect ADX support on the CURRENT linux machine.
	ADX_SUPPORT := $(shell if ([ -f "/proc/cpuinfo" ] && grep -q -e '^flags.*\badx\b' /proc/cpuinfo); then echo 1; else echo 0; fi)
else
# on non-linux machines, set the flag to 1 by default
	ADX_SUPPORT := 1
endif

# the crypto package uses BLST source files underneath which may use ADX instructions.
ifeq ($(ADX_SUPPORT), 1)
# if ADX instructions are supported, default is to use a fast ADX BLST implementation 
	ADX_FLAG := ""
else
# if ADX instructions aren't supported, this CGO flags uses a slower non-ADX BLST implementation 
	ADX_FLAG := "-O2 -D__BLST_PORTABLE__"
endif

# test all packages
.PHONY: test
test:
	CGO_ENABLED=1 CGO_CFLAGS=$(ADX_FLAG) go test -coverprofile=$(COVER_PROFILE) $(RACE_FLAG) $(if $(JSON_OUTPUT),-json,) $(if $(VERBOSE),-v,) ./...


# recurse through all subdirectories and run the argument command "cmd"
.PHONY: recurse
exclude ?= ""
recurse:
	find . -type d | while read dir; do \
	  skip="no"; \
	  for p in $$exclude; do \
	    case "$$dir" in \
	      "$$p"*) skip="yes"; break ;; \
	    esac; \
	  done; \
	  if [ "$$skip" = "no" ]; then \
	    (make $(cmd) path="$$dir") \
	  fi; \
	done

# format C code
.PHONY: c-format
path ?= ./
c-format:
	cd $(path) && \
	clang-format -style=llvm -dump-config > .clang-format && \
	if ls *.c >/dev/null 2>&1; then \
		clang-format -i *.c; \
	fi && \
	if ls *.h >/dev/null 2>&1; then \
		clang-format -i *.h; \
	fi && \
	rm -f .clang-format && \
	git diff --exit-code


# address sanitization and other checks
.SILENT: c-asan
path ?= ./
c-asan:
# - address sanitization and other checks (only on linux)
	cd $(path) && \
	if [ $(UNAME) = "Linux" ]; then \
		CGO_CFLAGS=$(ADX_FLAG) CC="clang -O0 -g -fsanitize=address -fno-omit-frame-pointer -fsanitize=leak -fsanitize=undefined -fno-sanitize-recover=all -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow -fno-sanitize=null -fno-sanitize=alignment" \
		LD="-fsanitize=address -fsanitize=leak" go test; \
		if [ $$? -ne 0 ]; then exit 1; fi; \
	else \
		echo "sanitization is only supported on Linux"; \
	fi; \

# memory sanitization
.SILENT: c-msan
path ?= ./
c-msan:
# - memory sanitization (only on linux and using clang) - (could use go test -msan)
# currently, this leads to many false positives, most likely because of assembly code not handled properly
# by asan. If you would like to run this command, you can use `NO_MSAN` to diable msan in some C functions.
# For instance "void NO_MSAN f() {...}" disables msan in function f. `NO_MSAN` is already defined in
# bls12381_utils.h
	cd $(path) && \
	if [ $(UNAME) = "Linux" ]; then \
		CGO_CFLAGS=$(ADX_FLAG) CC="clang -DMSAN -O0 -g -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins" \
		LD="-fsanitize=memory" go test; \
		if [ $$? -ne 0 ]; then exit 1; fi; \
	else \
		echo "sanitization is only supported on Linux"; \
	fi; \

# sanitize C code
.SILENT: c-sanitize
path ?= ./
c-sanitize: c-asan
# - address sanitization and other checks (only on linux)
# - memory sanitization (target m-san) is disabled because of multiple false positives
 


# Go tidy
.PHONY: go-tidy
go-tidy:
	go mod tidy -v
	git diff --exit-code

# Go lint
.PHONY: go-lint
go-lint: go-tidy
	# revive -config revive.toml
	golangci-lint run -v ./...
