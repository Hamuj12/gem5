from m5.params import *
from m5.proxy import *
from m5.SimObject import SimObject
# from m5.objects.ValuePredictor import ValuePredictor


class ValuePredictor(SimObject):
    type = "ValuePredictor"
    cxx_class = "gem5::lvp::ValuePredictor"  # Note the namespace change
    cxx_header = "cpu/lvp/value_pred.hh"  # Updated path

    lvpt_size = Param.Unsigned(2048, "Number of entries in the LVPT")
    lct_size = Param.Unsigned(2048, "Number of entries in the LCT")
    cvu_size = Param.Unsigned(128, "Number of entries in the CVU")