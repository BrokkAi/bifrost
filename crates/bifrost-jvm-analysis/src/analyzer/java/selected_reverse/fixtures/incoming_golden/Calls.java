package sample;
interface Action { void run(); }
class Base { void virtual() {} }
class Child extends Base { @Override void virtual() {} }
class Worker implements Action, Runnable, Comparable<Worker> {
    public void run() {}
    public int compareTo(Worker other) { return 0; }
    static void direct() {}
    static void referenced() {}
    Worker() {}
    void pick(Integer value) {}
    void pick(String value) {}
    void use(Base base, Action action) {
        direct();
        new Worker();
        pick(1);
        pick(null);
        base.virtual();
        action.run();
        Runnable callback = new Worker();
        callback.run();
        compareTo(this);
        Runnable reference = Worker::referenced;
    }
}
