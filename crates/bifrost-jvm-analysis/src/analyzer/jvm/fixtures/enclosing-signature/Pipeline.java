package enclosing;
import java.util.function.Consumer;
import java.util.function.Function;
public class Pipeline<T> {
    public Pipeline() {
        Consumer<T> sink = new Consumer<T>() {
            public void accept(T value) {}
        };
    }
    public <R> Pipeline<R> map(Function<? super T, ? extends R> mapper) {
        return new Pipeline<R>() {
            public Consumer<T> wrap(Consumer<R> downstream) {
                return new Consumer<T>() {
                    public void accept(T value) { downstream.accept(mapper.apply(value)); }
                    public R last() { return null; }
                };
            }
        };
    }
    public static <S> Consumer<S> each() {
        return new Consumer<S>() {
            public void accept(S value) {}
        };
    }
}
