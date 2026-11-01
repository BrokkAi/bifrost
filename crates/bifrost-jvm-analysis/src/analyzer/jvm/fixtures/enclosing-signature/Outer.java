package enclosing;
import java.util.List;
public class Outer<T> {
    public class Inner {
        public T value;
        public T get() { return value; }
        public void put(List<T> values) {}
    }
    public Object local() {
        class Local {
            public <U> T get(U input) { return null; }
        }
        return new Local();
    }
}
