import java.util.List;
@interface Mark { String value(); }
@Mark("header")
class Parent { Parent(Object p) {} }
class Fixture extends Parent {
    static Object s = target();
    Object i = target();
    static { target(); }
    { target(); }
    Fixture() { super(target()); }
    void method(List<String> input) throws RuntimeException {
        target();
        Runnable lambda = () -> target();
        class Local { void run() { target(); } }
        Object anonymous = new Parent(target()) { void run() { target(); } };
        Object ordinary = new Parent(target());
    }
    static Object target() { return null; }
}
enum Choice { A(target()) { void run() { target(); } }; static Object target() { return null; } }
interface Constants { Object VALUE = Choice.target(); }
class FieldLambda { Runnable field = () -> Fixture.target(); }
class LambdaLocal { Runnable field = () -> { class Local { void run() { Fixture.target(); } } }; }
enum EnumAnonymous { A(new Parent(Fixture.target()) { void run() { Fixture.target(); } }); EnumAnonymous(Object value) {} }
class BodyAnnotation { void run() { @Mark("value") Object local = Fixture.target(); } }
