# Differential test: compare gobjcopy with GNU objcopy.
# Self-check today: GOBJCOPY=/usr/bin/objcopy make diff-test
.PHONY: diff-test
diff-test:
	GOBJCOPY=/usr/bin/objcopy go test ./test -run TestDifferential -v -count=1
