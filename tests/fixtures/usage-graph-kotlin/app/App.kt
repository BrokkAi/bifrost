package app

import lib.Base
import lib.Counter
import lib.Derived
import lib.Marker
import lib.Registry
import lib.shout
import lib.topLevelHelper

class Consumer {

    fun greet(name: String): String {
        return "consumer " + name
    }
}

fun viaInstance(): String {
    val base = Base()
    return base.greet("world")
}

fun viaWrongReceiver(): String {
    val other = Consumer()
    return other.greet("world")
}

fun viaCompanion(): Base {
    return Base.of()
}

fun viaObject(): Boolean {
    return Registry.register("name")
}

fun viaConstructor(): Counter {
    return Counter(1)
}

fun viaProperty(counter: Counter): Int {
    return counter.count
}

fun viaInherited(): String {
    val derived = Derived()
    return derived.helper()
}

fun viaOverride(): String {
    val derived = Derived()
    return derived.greet("world")
}

fun viaTopLevel(): String {
    return topLevelHelper()
}

fun viaExtension(): String {
    val base = Base()
    return base.shout()
}

fun viaUnprovenReceiver(values: List<Base>): String {
    return values.map { item -> item.greet("x") }.first()
}

class SelfCaller {

    fun outer(): String {
        return inner()
    }

    private fun inner(): String {
        return "inner"
    }
}

@Marker(Base::class)
fun viaClassLiteralAnnotation(): String {
    return "annotated"
}

fun viaShadowedClassLiteral(): String {
    val Registry = "text"
    val kind = Registry::class
    return kind.toString()
}
