fn main() {
    cc::Build::new()
        .file("src/breakpoint.c")
        .opt_level(2)
        .compile("breakpoint")
}
