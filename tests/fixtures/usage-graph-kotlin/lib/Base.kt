package lib

open class Base {

    open fun greet(name: String): String {
        return "hello " + name
    }

    fun helper(): String {
        return "helper"
    }

    fun unused(): String {
        return "unused"
    }

    companion object {

        fun of(): Base {
            return Base()
        }
    }
}

class Derived : Base() {

    override fun greet(name: String): String {
        return "derived " + name
    }
}

fun Base.shout(): String {
    return "shout"
}

annotation class Marker(val of: kotlin.reflect.KClass<*>)
