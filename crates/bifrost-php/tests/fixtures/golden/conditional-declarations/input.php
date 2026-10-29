<?php
class A { function touch() {} }
class B { function touch() {} }
class ParentOwner { function touch() {} }
if ($choice) {
    class Relative { public self|null $next; function touch() {} function consume() { $this->next->touch(); } }
    class RelativeConflict extends ParentOwner { public self $next; function touch() {} function consume() { $this->next->touch(); } }
    class Written { public $value; function __construct() { $this->value=new A(); } function consume() { $this->value->touch(); } }
    class Conflict { public $value; function __construct() { $this->value=new A(); } function consume() { $this->value->touch(); } }
    function declared(): A { return new A(); }
    /** @return A */ function factory() { return new A(); }
    /** @return A */ function conflicting() { return new A(); }
    class Ambiguous { function touch() {} }
} else {
    class Relative { public self|null $next; function touch() {} function consume() { $this->next->touch(); } }
    class RelativeConflict extends ParentOwner { public parent $next; function touch() {} function consume() { $this->next->touch(); } }
    class Written { public $value; function __construct() { $this->value=new A(); } function consume() { $this->value->touch(); } }
    class Conflict { public $value; function __construct() { $this->value=new B(); } function consume() { $this->value->touch(); } }
    function declared(): A { return new A(); }
    /** @return A */ function factory() { return new A(); }
    /** @return B */ function conflicting() { return new B(); }
}
function doc_agreement() { factory()->touch(); }
function doc_conflict() { conflicting()->touch(); }
function member_ambiguity(Ambiguous $value) { $value->touch(); }
function declared_agreement() { declared()->touch(); }
