#ifndef __CPU_LVP_VALUE_PRED_HH__
#define __CPU_LVP_VALUE_PRED_HH__

#include "base/statistics.hh"
#include "base/types.hh"
#include "cpu/inst_seq.hh"
#include "params/ValuePredictor.hh"
#include "sim/sim_object.hh"

namespace gem5 {
namespace lvp {  // New namespace

class ValuePredictor : public SimObject
{
// LCT entry structure - 2-bit saturating counter

public:
/// Load Confidence Table states
enum class LCTState {
    DONT_PREDICT_1 = 0,  // Strongly don't predict
    DONT_PREDICT_2 = 1,  // Weakly don't predict
    PREDICT        = 2,  // Weakly predict
    CONSTANT       = 3   // Strongly predict (constant)
};
private:
    struct LCTEntry {
        LCTState state;    // Current state of the prediction counter
        InstSeqNum lastUpdate;    // Sequence number of last instruction that updated this entry

        LCTEntry() : state(LCTState::DONT_PREDICT_1), lastUpdate(0) {}

        // Increment counter on correct prediction
        void incrementCounter() {
            unsigned s = static_cast<unsigned>(state);
            if (s < static_cast<unsigned>(LCTState::CONSTANT))
                state = static_cast<LCTState>(s + 1);
        }

        // Decrement counter on incorrect prediction
        void decrementCounter() {
            unsigned s = static_cast<unsigned>(state);
            if (s > static_cast<unsigned>(LCTState::DONT_PREDICT_1))
                state = static_cast<LCTState>(s - 1);
        }

        bool shouldPredict() const {
            return state >= LCTState::PREDICT;
        }
    };
    
    public:
    typedef ValuePredictorParams Params;

    ValuePredictor(const Params &p);
    ~ValuePredictor();

    void reset();

    /**
     * Predicts the value for a load instruction based on its PC.
     * @param pc The program counter of the load instruction.
     * @param inst_seq_num The sequence number of the instruction.
     * @param valid Output parameter that indicates if the prediction should be used.
     * @return The predicted value.
     */
    std::pair<uint64_t,bool> predictValue(Addr pc, Addr upc, InstSeqNum inst_seq_num);

    /**
     * Updates the value prediction table with the actual value from a load.
     * @param pc The program counter of the load instruction.
     * @param inst_seq_num The sequence number of the instruction.
     * @param actual_value The actual value loaded from memory.
     * @param prediction_correct Whether the prediction was correct.
     */
    bool update(Addr pc, Addr upc, InstSeqNum inst_seq_num, uint64_t actual_value);

    /**
     * Squash all value predictions from instructions after the given sequence number.
     * @param inst_seq_num The sequence number to squash after.
     */
    void squash(InstSeqNum inst_seq_num);

    /** 
    * Checks if a memory address is in the CVU
    * @param addr The memory address to check
    * @param value Output parameter for the predicted value
    * @param loadPC Output parameter for the PC of the instruction
    * @return True if the address is in the CVU and valid
    */
    bool checkCVU(Addr addr, uint64_t &value, Addr &loadPC);

    /**
    * Invalidates a CVU entry if it exists
    * @param addr The memory address to invalidate
    */
    void invalidateCVU(Addr addr);

    /**
    * Updates the CVU with a new constant value
    * @param addr The memory address
    * @param pc The PC of the instruction
    * @param value The constant value
    */
    void updateCVU(Addr addr, Addr pc, uint64_t value);

    /**
     * Gets the current prediction state for an instruction at the given address.
     * @param pc The program counter of the instruction.
     * @return The current state of the prediction counter.
     */
     LCTState getLCTState(Addr pc, Addr upc) const {
        unsigned idx = hash(pc, upc);
        return lct[idx].state;
    }

    /** 
      * Force the LCT state for a given load‐PC to something new.
      * (e.g. on a store to the same address, demote back to DONT_PREDICT)
      */
      void setLCTState(Addr pc, Addr upc, LCTState newState);

  private:
    // LVPT entry structure
    struct LVPTEntry {
        uint64_t predictedValue;  // The last value seen for this load
        bool valid;               // Whether the entry contains a valid prediction
        InstSeqNum lastUpdate;    // Sequence number of last instruction that updated this entry

        LVPTEntry() : predictedValue(0), valid(false), lastUpdate(0) {}
    };

    // CVU entry structure
    struct CVUEntry {
        Addr dataAddr;        // Memory address this entry represents
        Addr instrAddr;       // PC of the instruction that loads from this address
        uint64_t value;       // Constant value at this address
        bool valid;           // Whether this entry is valid
        
        CVUEntry() : dataAddr(0), instrAddr(0), value(0), valid(false) {}
        CVUEntry(Addr _dataAddr, Addr _instrAddr, uint64_t _value) 
            : dataAddr(_dataAddr), instrAddr(_instrAddr), value(_value), valid(true) {}
    };

    /** Constant Verification Unit - keeps track of constant memory locations */
    std::vector<CVUEntry> cvu;
    unsigned cvuSize;

    /** Hash function for the CVU */
    unsigned cvuHash(Addr addr) const {
        return (addr >> 2) & (cvuSize - 1);
    }


    // Configuration parameters
    const unsigned lvptSize;      // Number of entries in the LVPT
    const unsigned lctSize;       // Number of entries in the LCT

    // The LVPT and LCT tables
    std::vector<LVPTEntry> lvpt;
    std::vector<LCTEntry> lct;

    // Hash function to index into the tables
    unsigned hash(Addr pc, Addr upc) const {
        // Simple hash function - can be made more sophisticated
        return ((pc >> 2) ^ (upc << 1)) & (lvptSize-1);
    }

    // Statistics
    struct ValuePredictorStats : public statistics::Group {
        statistics::Scalar predictions;
        statistics::Scalar predictionsUsed;
        statistics::Scalar correctPredictions;
        statistics::Scalar mispredictions;

        ValuePredictorStats(statistics::Group *parent);
    } stats;
};

} // namespace lvp
} // namespace gem5

#endif // __CPU_LVP_VALUE_PRED_HH__