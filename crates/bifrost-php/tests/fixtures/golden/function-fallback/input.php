<?php
namespace {
    class A { function touch() {} }
    function make(): A { return new A(); }
}
namespace N {
    class make {}
    function fallback() { make()->touch(); }
}
namespace M {
    class B { function touch() {} }
    function make(): B { return new B(); }
    function shadowed() { make()->touch(); }
}
