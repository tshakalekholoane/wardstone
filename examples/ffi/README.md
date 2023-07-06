# `ffi`

The following in an example of how to call the `wardstone` Rust library from C.

## Instructions

First compile the Rust library and generate the bindings using the following.

```bash
cargo build --release
```

The static library and associated header file will be placed in the `target` directory in the root directory of this repository.

Finally, compile the C example and run it using the following commands in the current directory. This assumes you are on a Unix system.

```bash
cc ./main.c -L../../target/release/ -I../../target/ -lwardstone 
./a.out
```
On Linux, you have to set `LD_LIBRARY_PATH=../../target/release/` before running `./a.out`.

If everything went well, the assertions should pass silently and the program output should be empty.
