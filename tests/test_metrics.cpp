#include "canshield/metrics.hpp"
#include "test_framework.hpp"

using canshield::ConfusionMatrix;

TEST_CASE("ConfusionMatrix rates default to zero with no data") {
    ConfusionMatrix cm;
    CHECK_EQ(cm.precision(), 0.0);
    CHECK_EQ(cm.recall(), 0.0);
    CHECK_EQ(cm.f1(), 0.0);
    CHECK_EQ(cm.accuracy(), 0.0);
    CHECK_EQ(cm.fpr(), 0.0);
}

TEST_CASE("ConfusionMatrix computes rates from added samples") {
    ConfusionMatrix cm;
    cm.add(true, true);    // tp
    cm.add(true, false);   // fn
    cm.add(false, true);   // fp
    cm.add(false, false);  // tn

    CHECK_EQ(cm.precision(), 0.5);
    CHECK_EQ(cm.recall(), 0.5);
    CHECK_EQ(cm.f1(), 0.5);
    CHECK_EQ(cm.accuracy(), 0.5);
    CHECK_EQ(cm.fpr(), 0.5);
}

TEST_CASE("ConfusionMatrix operator+= merges counts") {
    ConfusionMatrix a, b;
    a.add(true, true);
    b.add(false, true);
    b.add(false, false);
    a += b;

    CHECK_EQ(a.tp, 1u);
    CHECK_EQ(a.fp, 1u);
    CHECK_EQ(a.tn, 1u);
    CHECK_EQ(a.fn, 0u);
}

int main() { return canshield::test::run_all(); }
