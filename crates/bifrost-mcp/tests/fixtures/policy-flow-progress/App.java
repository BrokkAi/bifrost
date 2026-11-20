// Test-only flow fixture: both selector roles bind and the flow reaches a solve.
class App {
    static Object source() { return null; }
    static void sink(Object value) {}
    void run() { sink(source()); }
}
