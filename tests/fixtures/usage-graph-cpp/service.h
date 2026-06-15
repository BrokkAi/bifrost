#ifndef EXAMPLE_SERVICE_H
#define EXAMPLE_SERVICE_H

namespace example {

class Service {
public:
    void run() {}
    void unused() {}
    static void helper() {}
};

class Other {
public:
    void run() {}
};

void freeHelper() {}

} // namespace example

#endif
