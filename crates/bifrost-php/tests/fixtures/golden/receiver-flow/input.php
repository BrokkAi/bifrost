<?php
class A { function run() {} function touch() {} }
class B { function touch() {} }
class Both { function run() {} }
function tick() {}
function alias_union(A|B $value) { $copy = $value; $copy->run(); }
function ambiguous_union(A|Both $value) { $copy = $value; $copy->run(); }
function guarded($value) {
    if (!($value instanceof A)) return;
    tick();
    $value->touch();
}
function reassigned($value) {
    if (!($value instanceof A)) return;
    $value = new B();
    $value->touch();
}
function loop_guard($unknown) {
    foreach ($unknown as $value) {
        if (!($value instanceof A)) continue;
        $value->touch();
    }
}
function nonexiting($value) {
    if (!($value instanceof A)) tick();
    $value->touch();
}
function outside_guard($value) {
    if (!($value instanceof A)) return;
    function independent($value) { $value->touch(); }
    $closure = function ($value) { $value->touch(); };
}
class Collections {
    /** @var A[] */ public $items;
    function braced() { foreach ($this->items as $item) { $item->touch(); } }
    function unbraced() { foreach ($this->items as $item) $item->touch(); }
}
class Constructed {
    public $value;
    function __Construct() { $this->value = new A(); }
    function consume() { $this->value->touch(); }
}
class Base { function run() {} }
class Child extends Base {
    function consume(parent $value) { $value->run(); }
    function uppercase(PARENT $value) { $value->run(); }
    function same(self $value) { $value->run(); }
}
