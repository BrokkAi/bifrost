package boundary22;
class A { <T> void generic() {} void plain() {} void g(A a) { generic(); a.<String>plain(); } }
