#include "service.h"

namespace example {

class Consumer {
public:
    void viaInstance() {
        Service s;
        s.run();
    }

    void viaPointer(Service* p) {
        p->run();
    }

    void viaStatic() {
        Service::helper();
    }

    void callsLocal() {
        local();
    }

    void recurse() {
        recurse();
    }

    void wrongReceiver(Other* o) {
        o->run();
    }

    Service* makeService() {
        return new Service();
    }

    void viaFree() {
        freeHelper();
    }

    void local() {}
};

} // namespace example
