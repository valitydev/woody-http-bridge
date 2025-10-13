# Woody HTTP Bridge

   Если WebConfig поставляется как стартер, лучше оставить в нём только общий фильтр и вынести извлечение токена в отдельный бином контракта
   (например, TokenPathResolver), чтобы каждый сервис подключал свою реализацию. По умолчанию можно предоставить “no-op” реализацию, а в конкретном
   модуле-потребителе регистрировать нужный себе паттерн и правило allow-list. Так стартер останется универсальным, а бизнес-специфика не будет
   «зашита» внутрь общей библиотеки.
   
   ⛬  План реализации

   1. Базовая инфраструктура
     •  Вынести ServletAllowList в общий пакет.
     •  Создать интерфейс RestPortModule с методами для REST allow-list’а, набора URL-шаблонов и обработки запроса (вернуть enum Continue/Handled).
     •  Создать интерфейс ServerPortModule (для API) с аналогичным контрактом.

   2. Рефакторинг WebConfig
     •  Заменить поле tokenExtractor и связанную логику на внедрение RestPortModule (обязательный) и ObjectProvider<ServerPortModule> (опциональный).
     •  Разбить один фильтр на три FilterRegistrationBean:
       1. RestPortSecurityFilter — проверка порт/allow-list, вызов module.beforeChain, при успехе опциональный woodyFlow.createServiceFork.
       2. ServerPortServletFilter — допускает @WebServlet + служебные эндпоинты.
       3. ServerPortApiFilter — подключается только при наличии ServerPortModule, проверяет allow-list API-путей и вызывает модульную логику (с woodyFlow.createServiceFork, если нужно).
     •  Актуализировать сбор ServletRegistration для server‑порта и общее поведение 404.

   3. Модуль для адаптера
     •  Реализовать AdapterRestPortModule: получает CallbackTokenExtractor, CallbackTokenCipher, SecretService, TimerProperties, формирует REST allow-list (на основе extractor.restEndpoint и/или
        расширений), валидирует токены и возвращает Continue.
     •  Перенести существующую токенную логику из WebConfig внутрь этого модуля.
     •  Подключить CallbackTokenContractVerifier к модулю (через @ConditionalOnBean(AdapterRestPortModule)).

   4. Модуль для API-сервисов
     •  Реализовать ApiServerPortModule: конфигурируемый список allow-list префиксов/эндпоинтов, woodyFlow.createServiceFork, headersNormalizer/traceContextApplier как в Wachter.
     •  Обеспечить, чтобы модуль мог внедряться потребителем через @Bean.

   5. Интеграция с Wachter
     •  Добавить зависимость на стартер.                                                                •  Зарегистрировать ApiServerPortModule с нужными путями (например, /wachter/v1/**) и
                                                                                                           зависимостями (WoodyTracingFilter).
                                                                                                          •  Удалить кастомный WebConfig Wachter’а.

   6. Тестирование
     •  Обновить существующие тесты (в частности, WebConfigFilterTest, ProviderControllerTest, PaymentFlowTest) с учётом новой структуры фильтров/модулей.
     •  Добавить тесты на ApiServerPortModule и смешанные сценарии (REST + API).
     •  Запустить mvn -B test.

   7. Финиш
     •  Проверить ktlint, checkstyle.
     •  Подготовить краткое резюме изменений.

>  * что еще нужно знать явно для плана модели с чистой сессией и контекстом? то что у тебя есть в контексте в данный момент, не явное понимание и не зафиксированное

⛬  Неявные зависимые знания, которые стоит зафиксировать

   1. Двухпортовая архитектура: сервис слушает REST-порт (в server.rest.port) и “серверный” порт (server.port); фильтры обязаны сравнивать с фактическим request.localPort.
   2. Woody-трассировка: WoodyFlow и связанные утилиты (TraceContext, WoodyTracingFilter и т.п.) уже есть в проекте и должны использоваться для форка сервиса/трейсинга там, где модуль этого требует.
   3. Token security: CallbackTokenCipher, SecretService, TimerProperties.redirectTimeoutMin и CallbackVerificationPayload — доступные бины, которые модуль адаптера обязан инжектить и использовать,
      стартёр не создаёт их сам.
   4. Контракт URL: CallbackTokenContract и CallbackTokenExtractor (поставляются потребителем) диктуют, какие REST-пути разрешены и как извлекается токен; CallbackTokenContractVerifier выполняется
      только если бины для адаптерного сценария существуют.
│ Rejected Specification (for reference):                                                                                                                                 │
│                                                                                                                                                                         │
│ Предпосылки                                                                                                                                                             │
│ •  Сервис использует два порта: REST (server.rest.port) и server (server.port); фильтры обязаны проверять request.localPort.                                            │
│ •  Все сценарии, требующие трассировки, должны вызывать woodyFlow.createServiceFork и/или логику Woody tracing (как в Wachter).                                         │
│ •  Валидация токена опирается на существующие бины CallbackTokenCipher, SecretService, TimerProperties.redirectTimeoutMin и CallbackVerificationPayload – стартёр их не │
│     создаёт.                                                                                                                                                            │
│ •  REST-пути и извлечение токена задаются потребительскими CallbackTokenExtractor и CallbackTokenContract; CallbackTokenContractVerifier должен активироваться только   │
│    когда используется адаптерный модуль.                                                                                                                                │
│ Шаги                                                                                                                                                                    │
│                                                                                                                                                                         │
│ 1. Инфраструктура модулей                                                                                                                                               │
│   •  Вынести ServletAllowList в общий пакет/файл.                                                                                                                       │
│   •  Создать интерфейсы RestPortModule и ServerPortModule с методами: allowList(), filterPatterns(), beforeChain(request, response, filterChain, woodyFlow) и флагом    │
│      requiresWoodyFork.                                                                                                                                                 │
│ 2. Рефакторинг WebConfig                                                                                                                                                │
│   •  Инжектировать RestPortModule (обязательный) и ObjectProvider<ServerPortModule> (опциональный).                                                                     │
│   •  Разбить текущий фильтр на три FilterRegistrationBean:                                                                                                              │
│     1. RestPortSecurityFilter – проверка allow-list REST-порта, вызов restModule.beforeChain; при requiresWoodyFork оборачивать в woodyFlow.createServiceFork.          │
│     2. ServerPortServletFilter – пропускает @WebServlet + /actuator/health + /error, выполняет filterChain.doFilter.                                                    │
│     3. ServerPortApiFilter – регистрируется только если есть ServerPortModule; проверяет API allow-list, выполняет модульную логику и опциональный                      │
│        woodyFlow.createServiceFork.                                                                                                                                     │
│   •  Обновить сбор allow-list’а для server порта через ServletRegistration.                                                                                             │
│                                                                                                                                                                         │
│ 3. AdapterRestPortModule                                                                                                                                                │
│   •  Реализовать модуль, который                                                                                                                                        │
│     •  Использует CallbackTokenExtractor для формирования полного REST allow-list.                                                                                      │
│     •  Извлекает/декодирует токен, использует CallbackTokenCipher + SecretService + TimerProperties для проверки срока действия.                                        │
│     •  Устанавливает CallbackVerificationPayload в request и возвращает Continue.                                                                                       │
│   •  Перенести токенную логику из WebConfig в модуль.                                                                                                                   │
│   •  Подключить CallbackTokenContractVerifier через @ConditionalOnBean(AdapterRestPortModule::class).                                                                   │
│                                                                                                                                                                         │
│ 4. ApiServerPortModule                                                                                                                                                  │
│   •  Реализовать модуль для API путей: конфигурируемый allow-list (список точных и префиксных путей), опциональная поддержка Woody tracing (headers normalizer, trace   │
│      applier).                                                                                                                                                          │
│   •  Возвращать requiresWoodyFork = true, оборачивать filterChain.doFilter в woodyFlow.createServiceFork.                                                               │
│ 5. Интеграция Wachter                                                                                                                                                   │
│   •  Подключить стартер в проекте Wachter.                                                                                                                              │
│   •  Зарегистрировать ApiServerPortModule (с путями контроллера WachterController, tracing зависимостями).                                                              │
│   •  Удалить собственный WebConfig Wachter.                                                                                                                             │
│                                                                                                                                                                         │
│ 6. Тестирование и проверка                                                                                                                                              │
│   •  Обновить WebConfigFilterTest, ProviderControllerTest, PaymentFlowTest согласно новой архитектуре фильтров/модулей.                                                 │
│   •  Добавить тесты для ApiServerPortModule и комбинированных сценариев (REST + API).                                                                                   │
│   •  Запустить mvn -B test и убедиться, что ktlint/checkstyle проходят.                                                                                                 │
│                                                                                                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

                              

## Background

- Gateway services such as Wachter receive HTTP requests that may already contain Woody (`woody.*`, `x-woody-*`) and W3C (`traceparent`) tracing headers.
- Current Wachter implementation normalizes incoming headers, hydrates Woody `TraceContext`, ensures OpenTelemetry SERVER spans are created, and forwards normalized headers to downstream Woody RPC clients.
- The `woody_java` library remains the tracing foundation: the bridge focuses on HTTP transport glue while reusing the standard header/MDC facilities described in `woody_trace_enhancement_plan.md`.
- OpenTelemetry requires explicit SERVER span lifecycle management (status, errors, `span.end()`), while Woody RPC handles span lifecycle internally once the Woody flow is forked.
- HTTP clients that call Wachter expect plain HTTP responses; Woody-specific response metadata is only required on the RPC leg.

## Concept

Create a reusable "Woody HTTP Bridge" starter that bridges HTTP traffic with Woody and OpenTelemetry tracing so that any HTTP gateway can:

1. Extract and normalize Woody/W3C headers from incoming HTTP requests.
2. Hydrate the current Woody `TraceContext` before executing business logic.
3. Ensure an OpenTelemetry SERVER span is started, annotated, and completed per spec.
4. Provide helpers for forwarding normalized headers when making downstream Woody RPC calls, delegating codec constants and normalizers to `woody_java` wherever possible.

## Implementation Plan

1. **Project Setup**
   - Publish a `woody-http-bridge` library (Maven/Gradle) with starter-style auto-configuration.
   - Depend on `woody-java`, `opentelemetry-api`, and Servlet/Spring Web abstractions.

2. **Incoming Request Pipeline**
   - `WoodyHttpBridgeFilter` (Servlet `Filter` or `OncePerRequestFilter`) orchestrating header normalization, `TraceContext` hydration, and telemetry handling.
   - Pluggable `NormalizedHeadersStore` (default: request attributes) to persist merged headers for downstream usage.
   - `HeaderNormalizer` to merge `x-woody-*` into `woody.*`, capture `traceparent`, JWT metadata, and deadlines.
   - `TraceContextHydrator` to copy normalized IDs, deadline, and user identity extensions into the current Woody span.

3. **OpenTelemetry Integration**
   - `TelemetryBridge` responsible for starting/stopping SERVER spans, extracting parents (via `HttpServletRequestTextMapGetter`), injecting missing `traceparent` (`MapTextMapSetter`), and recording status/errors.

4. **Outgoing Request Helpers**
   - `OutgoingHeadersProvider` that combines stored normalized headers with live `TraceContext` values.
   - Optional interceptors for `RestClient`, `WebClient`, or manual helper to inject headers into arbitrary HTTP/RPC clients.

5. **Configuration & Extensibility**
   - Spring Boot auto-configuration with properties to enable/disable components, customize header mappings, and swap storage strategies.
   - Extension hooks for plugging in helper classes from `woody_java` (e.g., MDC utilities or shared header codecs).
   - Fallback manual registration API for non-Spring environments.

6. **Testing & Examples**
   - Unit tests for normalization, hydration, telemetry, and outgoing header composition.
   - Integration test with Mock MVC to verify end-to-end propagation.
   - Example application demonstrating gateway usage.

## Next Steps

- Align on API surface (naming, extension points) before coding.
- Decide which HTTP clients to support out of the box for outgoing propagation.
- Prepare publishing pipeline (group ID, versioning) and documentation once implementation is ready.
