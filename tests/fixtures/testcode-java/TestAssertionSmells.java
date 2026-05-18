import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TestAssertionSmells {
    @Test
    void tautologicalAssertion() {
        String value = "x";
        assertEquals(value, value);
    }

    @Test
    void shallowAssertionOnly() {
        Object value = new Object();
        assertNotNull(value);
    }

    @Test
    void noAssertions() {
        helper();
    }

    @Test
    void anonymousTestDouble() {
        Runnable runnable = new Runnable() {
            @Override
            public void run() {}
        };
        runnable.run();
    }

    @Test
    void assertJConstantTruth() {
        assertThat(true).isTrue();
    }

    private void helper() {
        assertTrue(true);
    }
}
