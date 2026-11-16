package superreceiver;

public class Fixture {
    String describe() {
        return super.toString();
    }
}

class Base {
    public static int FLAG = 1;

    public void m() {}
}

class Overridden extends Base {
    @Override
    public void m() {
        super.m();
    }
}

class Hiding extends Base {
    public static int FLAG = 2;

    int read() {
        return super.FLAG;
    }
}

class SelfCall extends Base {
    @Override
    public void m() {
        this.m();
        m();
    }
}

class SkipParent extends Base {}

class SkipLeaf extends SkipParent {
    @Override
    public void m() {
        super.m();
    }
}

class Anonymous {
    Base make() {
        return new Base() {
            @Override
            public void m() {
                super.m();
            }
        };
    }
}

enum Letter {
    A {
        @Override
        String describe() {
            return super.describe();
        }
    },
    B;

    String describe() {
        return "member";
    }
}

class MissingUser extends Missing {
    @Override
    public void m() {
        super.m();
    }
}

class MethodReference extends Base {
    @Override
    public void m() {}

    Runnable task() {
        return super::m;
    }
}

class Secret {
    private void hidden() {}
}

class SecretChild extends Secret {
    void reveal() {
        super.hidden();
    }
}

class Outer {
    static class Inner {
        private void p() {}
    }

    static class InnerChild extends Inner {
        void q() {
            super.p();
        }
    }
}
