#ifndef SIMPLE_TEST_H
#define SIMPLE_TEST_H

#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

// Contatori globali per i test
struct TestStats {
    int total;
    int passed;
    int failed;

    TestStats() : total(0), passed(0), failed(0) {
    }
};

static TestStats globalStats;

// Macro per le asserzioni
#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("  ❌ FAIL: %s:%d - Expected true, got false: %s\n", \
                   __FILE__, __LINE__, #condition); \
            return false; \
        } \
    } while(0)

#define ASSERT_FALSE(condition) \
    do { \
        if (condition) { \
            printf("  ❌ FAIL: %s:%d - Expected false, got true: %s\n", \
                   __FILE__, __LINE__, #condition); \
            return false; \
        } \
    } while(0)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("  ❌ FAIL: %s:%d - Expected: %p, Actual: %p\n", \
            __FILE__, __LINE__, (void*)(uintptr_t)(expected), (void*)(uintptr_t)(actual)); \
            return false; \
        } \
    } while(0)

#define ASSERT_NEQ(expected, actual) \
    do { \
        if ((expected) == (actual)) { \
            printf("  ❌ FAIL: %s:%d - Expected values to be different\n", \
            __FILE__, __LINE__); \
            return false; \
        } \
    } while(0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != nullptr) { \
            printf("  ❌ FAIL: %s:%d - Expected NULL pointer\n", \
                   __FILE__, __LINE__); \
            return false; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == nullptr) { \
            printf("  ❌ FAIL: %s:%d - Expected non-NULL pointer\n", \
                   __FILE__, __LINE__); \
            return false; \
        } \
    } while(0)

#define ASSERT_GT(a, b) \
    do { \
        if (!((a) > (b))) { \
            printf("  ❌ FAIL: %s:%d - Expected %lld > %lld\n", \
            __FILE__, __LINE__, (long long)(a), (long long)(b)); \
            return false; \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("  ❌ FAIL: %s:%d - Expected: '%s', Actual: '%s'\n", \
                   __FILE__, __LINE__, (expected), (actual)); \
            return false; \
        } \
    } while(0)

// Classe base per i test
class TestCase {
public:
    virtual ~TestCase() {
    }

    virtual void setup() {
    }

    virtual void teardown() {
    }

    virtual bool run() = 0;

    virtual const char *name() = 0;
};

// Registry per i test
class TestRegistry {
private:
    std::vector<TestCase *> tests;

public:
    static TestRegistry &instance() {
        static TestRegistry registry;
        return registry;
    }

    void registerTest(TestCase *test) {
        tests.push_back(test);
    }

    int runAll() {
        printf("\n");
        printf("-----------------------------------------------------------------\n");
        printf("                  OES TEST SUITE                                  \n");
        printf("-----------------------------------------------------------------\n\n");

        for (TestCase *test: tests) {
            globalStats.total++;
            printf("Running: %s\n", test->name());

            test->setup();
            bool passed = test->run();
            test->teardown();

            if (passed) {
                globalStats.passed++;
                printf(" - PASS\n");
            } else {
                globalStats.failed++;
            }
            printf("\n");
        }

        printf("--------------------------------------------------------------\n");
        printf("Test Results:\n");
        printf("  Total:  %d\n", globalStats.total);
        printf("  Passed: %d (%.1f%%)\n", globalStats.passed,
               globalStats.total > 0 ? (100.0 * globalStats.passed / globalStats.total) : 0.0);
        printf("  Failed: %d\n", globalStats.failed);
        printf("--------------------------------------------------------------\n\n");

        return globalStats.failed > 0 ? 1 : 0;
    }

    ~TestRegistry() {
        tests.clear();
    }
};

// Macro per definire un test
#define TEST(TestName) \
    class TestName : public TestCase { \
    public: \
        TestName() { TestRegistry::instance().registerTest(this); } \
        const char* name() override { return #TestName; } \
        bool run() override; \
    }; \
    static TestName testInstance_##TestName; \
    bool TestName::run()

#endif // SIMPLE_TEST_H
