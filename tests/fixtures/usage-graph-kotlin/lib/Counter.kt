package lib

class Counter(var count: Int) {

    fun bump(): Int {
        return count
    }
}

object Registry {

    fun register(name: String): Boolean {
        return name.isNotEmpty()
    }
}

fun topLevelHelper(): String {
    return "top"
}
