package org.ugina;

import org.testng.annotations.Test;
import org.ugina.config.RateLimitProperties;
import org.ugina.ratelimit.RateLimitService;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class RateLimitServiceTest {

    /**
     * Создаёт сервис с лимитом capacity запросов в час.
     * Без Spring — конфиг собираем руками.
     */
    private RateLimitService serviceWithCapacity(int capacity) {
        RateLimitProperties props = new RateLimitProperties();
        props.getLogin().setCapacity(capacity);
        props.getLogin().setPeriodMinutes(60);
        return new RateLimitService(props);
    }

    @Test
    public void allowsRequestsWithinLimit() {
        RateLimitService service = serviceWithCapacity(3);
        RateLimitProperties.Limit limit = new RateLimitProperties.Limit();
        limit.setCapacity(3);
        limit.setPeriodMinutes(60);

        // первые 3 запроса проходят
        assertTrue(service.tryConsume("test-key", limit), "1-й запрос разрешён");
        assertTrue(service.tryConsume("test-key", limit), "2-й запрос разрешён");
        assertTrue(service.tryConsume("test-key", limit), "3-й запрос разрешён");
    }

    @Test
    public void blocksRequestsOverLimit() {
        RateLimitService service = serviceWithCapacity(3);
        RateLimitProperties.Limit limit = new RateLimitProperties.Limit();
        limit.setCapacity(3);
        limit.setPeriodMinutes(60);

        // исчерпываем лимит
        service.tryConsume("test-key", limit);
        service.tryConsume("test-key", limit);
        service.tryConsume("test-key", limit);

        // 4-й должен быть заблокирован
        assertFalse(service.tryConsume("test-key", limit), "4-й запрос заблокирован");
    }

    @Test
    public void differentKeysHaveSeparateBuckets() {
        RateLimitService service = serviceWithCapacity(1);
        RateLimitProperties.Limit limit = new RateLimitProperties.Limit();
        limit.setCapacity(1);
        limit.setPeriodMinutes(60);

        // у каждого ключа своё ведро
        assertTrue(service.tryConsume("ip-A", limit), "ip-A первый запрос разрешён");
        assertTrue(service.tryConsume("ip-B", limit), "ip-B первый запрос разрешён");

        // но второй для каждого — заблокирован
        assertFalse(service.tryConsume("ip-A", limit), "ip-A второй заблокирован");
        assertFalse(service.tryConsume("ip-B", limit), "ip-B второй заблокирован");
    }
}
