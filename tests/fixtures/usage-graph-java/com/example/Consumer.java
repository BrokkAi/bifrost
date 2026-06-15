package com.example;

public class Consumer {
    public int viaInstance() {
        Service s = new Service();
        return s.run();
    }

    public int viaStatic() {
        return Service.helper();
    }

    public Service makeService() {
        return new Service();
    }

    public int shadowed(Service run) {
        // `run` is a Service-typed parameter; `run.run()` resolves to
        // Service.run via the receiver type, not via the method name alone.
        return run.run();
    }

    public int wrongReceiver(Consumer other) {
        // `other` is a Consumer, which has no `run()`; resolving by receiver type
        // gives `Consumer.run` (not a node), so this must NOT edge to Service.run.
        return other.run();
    }

    public int shadowFallback() {
        // `Service` here is an untyped local that merely shares the Service
        // type's name; calling `run()` on it must NOT be reinterpreted as a
        // static call on the `Service` type.
        var Service = 42;
        return Service.run();
    }
}
