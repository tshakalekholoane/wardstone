# `ffi`

The following in an example of how to call the `wardstone` Rust library from C.

> **Note**:
> This requires a C compiler with some features from the C23 standard enabled.

# Instructions

First compile the Rust library using the following.

```bash
cargo build --release
```

And then compile the example binary and run it.

```bash
cc -std=c2x ./main.c -L../../target/release/ -lwardstone 
./a.out
```

If everything went well, the program output should be empty.
