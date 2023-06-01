# `ffi`

The following in an example of how to call the `wardstone` Rust library from C.

# Instructions

First compile the Rust library using the following.

```bash
cargo build --release
```

And then compile the example binary and run it.

```bash
cc ./main.c -L../../target/release/ -I../../ -lwardstone 
./a.out
```

If everything went well, the program output should be empty.
