#include "canshield/metrics.hpp"
#include "test_framework.hpp"

using canshield::Campaign;
using canshield::ConfusionMatrix;
using canshield::ScenarioResult;

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

TEST_CASE("Campaign aggregates frame counts, confusion matrices, and detections") {
    ScenarioResult a;
    a.attack = "rpm_spoof";
    a.total_frames = 100;
    a.detected = true;
    a.cm.add(true, true);   // tp
    a.cm.add(false, true);  // fp

    ScenarioResult b;
    b.attack = "flood";
    b.total_frames = 50;
    b.detected = false;
    b.cm.add(false, false);  // tn

    Campaign camp;
    camp.results = {a, b};

    CHECK_EQ(camp.total_frames(), 150u);
    CHECK_EQ(camp.detected_count(), 1);

    ConfusionMatrix agg = camp.aggregate_cm();
    CHECK_EQ(agg.tp, 1u);
    CHECK_EQ(agg.fp, 1u);
    CHECK_EQ(agg.tn, 1u);
    CHECK_EQ(agg.fn, 0u);
}

TEST_CASE("Campaign with no scenarios aggregates to all zeros") {
    Campaign camp;
    CHECK_EQ(camp.total_frames(), 0u);
    CHECK_EQ(camp.detected_count(), 0);
    CHECK_EQ(camp.aggregate_cm().tp, 0u);
}

int main() { return canshield::test::run_all(); }
