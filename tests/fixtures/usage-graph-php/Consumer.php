<?php

namespace App;

function topLevelHelper(): int
{
    return 42;
}

class Consumer
{
    public function viaInstance(): int
    {
        $s = new Service();
        return $s->run();
    }

    public function viaStatic(): int
    {
        return Service::helper();
    }

    public function viaParam(Service $svc): int
    {
        // `$svc` is a Service-typed parameter; resolves by receiver type.
        return $svc->run();
    }

    public function wrongReceiver(Consumer $other): int
    {
        // `$other` is a Consumer with no `run()`; resolves to Consumer.run
        // (not a node), so this must NOT edge to Service.run.
        return $other->run();
    }

    public function callsFreeFunction(): int
    {
        // Free function call attributes to the enclosing class method.
        return topLevelHelper();
    }

    public function makeService(): Service
    {
        return new Service();
    }

    public function selfRecursion(): int
    {
        // Self-call must not produce an edge.
        return $this->selfRecursion();
    }

    public function callsSelfMethod(): int
    {
        // `$this->` resolves to the enclosing class.
        return $this->viaInstance();
    }

    public function closureScopeIsolation(Service $svc): int
    {
        // The closure reassigns `$svc` to another type in its OWN scope; it must
        // not leak out, so the outer `$svc->run()` still resolves to Service.run.
        $fn = function () {
            $svc = new Consumer();
            return $svc;
        };
        $fn();
        return $svc->run();
    }
}
