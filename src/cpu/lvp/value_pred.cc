#include "cpu/lvp/value_pred.hh"  // Updated path

#include "base/intmath.hh"
#include "base/logging.hh"
#include "base/trace.hh"
#include "debug/ValuePredictor.hh"

namespace gem5 {
namespace lvp {  // New namespace

    ValuePredictor::ValuePredictorStats::ValuePredictorStats(statistics::Group *parent)
    : statistics::Group(parent),
      ADD_STAT(predictions, statistics::units::Count::get(),
               "Number of value predictions made"),
      ADD_STAT(predictionsUsed, statistics::units::Count::get(),
               "Number of value predictions used"),
      ADD_STAT(correctPredictions, statistics::units::Count::get(),
               "Number of correct value predictions"),
      ADD_STAT(mispredictions, statistics::units::Count::get(),
               "Number of incorrect value predictions")
{
}

ValuePredictor::ValuePredictor(const Params &p)
    : SimObject(p),
      lvptSize(p.lvpt_size),
      lctSize(p.lct_size),
      lvpt(lvptSize),
      lct(lctSize),
      cvuSize(p.cvu_size),
      cvu(cvuSize),
      stats(this)
{
    // Make sure the table sizes are powers of 2
    DPRINTF(ValuePredictor, "Value Predictor LVPT size: %d\n", lvptSize);
    DPRINTF(ValuePredictor, "Value Predictor LVPT parameter size: %d\n", p.lvpt_size);
    DPRINTF(ValuePredictor, "Value Predictor LCT size: %d\n", lctSize);
    DPRINTF(ValuePredictor, "Value Predictor LCT parameter size: %d\n", p.lct_size);

    if (lvptSize != p.lvpt_size)
        warn("LVPT size rounded down to %d", lvptSize);
    if (lctSize != p.lct_size)
        warn("LCT size rounded down to %d", lctSize);
}

ValuePredictor::~ValuePredictor()
{
}

void
ValuePredictor::reset()
{
    for (auto &entry : lvpt) {
        entry.valid = false;
        entry.predictedValue = 0;
        entry.lastUpdate = 0;
    }

    for (auto &entry : lct) {
        entry.state = LCTState::DONT_PREDICT_1;
        entry.lastUpdate = 0;
    }
}

std::pair<uint64_t,bool>
ValuePredictor::predictValue(Addr pc, Addr upc, InstSeqNum inst_seq_num)
{
    stats.predictions++;

    unsigned idx = hash(pc, upc);
    const LVPTEntry &lvptEntry = lvpt[idx];
    const LCTEntry &lctEntry = lct[idx];

    // First check if we should predict according to the LCT
    bool valid = lvptEntry.valid && lctEntry.shouldPredict();

    // print out the prediction state, convert to string using case
    std::string state;
    switch (lctEntry.state) {
        case LCTState::DONT_PREDICT_1:
            state = "DONT_PREDICT_1";
            break;
        case LCTState::DONT_PREDICT_2:
            state = "DONT_PREDICT_2";
            break;
        case LCTState::PREDICT:
            state = "PREDICT";
            break;
        case LCTState::CONSTANT:
            state = "CONSTANT";
            break;
        default:
            state = "UNKNOWN";
            break;
    }
    
    DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | Prediction state: %s\n",
            inst_seq_num, pc, upc, state);

    if (valid) {
        stats.predictionsUsed++;
    } else {
        DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | No prediction\n",
                inst_seq_num, pc, upc);
    }

    return {lvptEntry.predictedValue, valid};
}

bool
ValuePredictor::update(Addr pc, Addr upc, InstSeqNum inst_seq_num, uint64_t actual_value)
{
    unsigned idx = hash(pc, upc);
    LVPTEntry &lvptEntry = lvpt[idx];
    LCTEntry &lctEntry = lct[idx];

    // Update the confidence counter in the LCT
    if (lvptEntry.valid) {
        // print state of the LVPT entry
        std::string state;
        switch (lctEntry.state) {
            case LCTState::DONT_PREDICT_1:
                state = "DONT_PREDICT_1";
                break;
            case LCTState::DONT_PREDICT_2:
                state = "DONT_PREDICT_2";
                break;
            case LCTState::PREDICT:
                state = "PREDICT";
                break;
            case LCTState::CONSTANT:
                state = "CONSTANT";
                break;
            default:
                state = "UNKNOWN";
        }
        DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | LCT state before update: %s\n",
            inst_seq_num, pc, upc, state);

        if (actual_value == lvptEntry.predictedValue) {
            lctEntry.incrementCounter();
            stats.correctPredictions++;
            DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | Correct prediction, predicted value 0x%x, actual value 0x%x\n",
                    inst_seq_num, pc, upc, lvptEntry.predictedValue, actual_value);
        } else {
            lctEntry.decrementCounter();
            stats.mispredictions++;
            DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | Incorrect prediction, predicted value 0x%x, actual value 0x%x\n",
                    inst_seq_num, pc, upc, lvptEntry.predictedValue, actual_value);
        }

        switch (lctEntry.state) {
            case LCTState::DONT_PREDICT_1:
                state = "DONT_PREDICT_1";
                break;
            case LCTState::DONT_PREDICT_2:
                state = "DONT_PREDICT_2";
                break;
            case LCTState::PREDICT:
                state = "PREDICT";
                break;
            case LCTState::CONSTANT:
                state = "CONSTANT";
                break;
            default:
                state = "UNKNOWN";
        }
        DPRINTF(ValuePredictor, "[sn:%llu] (VP) PC %#llx.%#llx | LCT state after update: %s\n",
                inst_seq_num, pc, upc, state);

    }

    // Update the LVPT with the new value
    lvptEntry.predictedValue = actual_value;
    lvptEntry.valid = true;
    lvptEntry.lastUpdate = inst_seq_num;

    // Update the LCT's last update
    lctEntry.lastUpdate = inst_seq_num;
    return actual_value == lvptEntry.predictedValue;
}

void
ValuePredictor::squash(InstSeqNum inst_seq_num)
{
    // Invalidate all entries updated by instructions after the squashed one
    for (auto &entry : lvpt) {
        if (entry.lastUpdate >= inst_seq_num) {
            entry.valid = false;
        }
    }

    for (auto &entry : lct) {
        if (entry.lastUpdate >= inst_seq_num) {
            entry.state = LCTState::DONT_PREDICT_1;
        }
    }
}

bool
ValuePredictor::checkCVU(Addr addr, uint64_t &value, Addr &loadPC)
{
    unsigned idx = cvuHash(addr);
    CVUEntry &e = cvu[idx];
    if (e.valid && e.dataAddr == addr) {
        value   = e.value;
        loadPC  = e.instrAddr;    // grab the PC recorded
        return true;
    }
    return false;
}

void 
ValuePredictor::invalidateCVU(Addr addr)
{
    unsigned idx = cvuHash(addr);
    if (cvu[idx].valid && cvu[idx].dataAddr == addr) {
        cvu[idx].valid = false;
        DPRINTF(ValuePredictor, "Invalidating CVU entry for address %#x\n", addr);
    }
}

void 
ValuePredictor::updateCVU(Addr addr, Addr pc, uint64_t value)
{
    unsigned idx = cvuHash(addr);
    cvu[idx] = CVUEntry(addr, pc, value);
}

void
ValuePredictor::setLCTState(Addr pc, Addr upc, LCTState newState)
{
    unsigned idx = hash(pc, upc);
    auto &entry = lct[idx];
    entry.state      = newState;
}

} // namespace lvp
} // namespace gem5
