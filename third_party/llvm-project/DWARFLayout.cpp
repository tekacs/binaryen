//===- DWARFLayout.cpp - Lay out and relocate decoded DIEs ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "DWARFVisitor.h"
#include "llvm/DebugInfo/DWARF/DWARFExpression.h"
#include "llvm/ObjectYAML/DWARFEmitter.h"
#include "llvm/ObjectYAML/DWARFYAML.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/LEB128.h"
#include <algorithm>
#include <unordered_map>

using namespace llvm;
using namespace llvm::DWARFYAML;

namespace {
// Layout and reference rewriting share one owner. Original offsets never change;
// every pass resolves against the original target, not a previously relocated
// number. Scalar LEB widths only grow, so reference-width feedback terminates.
class InfoLayout : public Visitor {
  struct Reference {
    FormValue *Value;
    uint64_t Target;
    uint64_t Base;
    unsigned Width; // Zero denotes ref_udata, otherwise a fixed byte count.
    bool Relative;
  };

  bool Relocating;
  bool Collect = true;
  bool Moved = false;
  bool Opaque = false;
  uint64_t Position = 0;
  uint64_t Start = 0;
  Unit *Current = nullptr;
  unsigned ByteSize = 0;
  FormValue *Scalar = nullptr;
  std::unordered_map<uint64_t, uint64_t> Positions;
  std::vector<Reference> References;

  static unsigned offsetSize(const Unit &CU) {
    return CU.Length.isDWARF64() ? 8 : 4;
  }

  static void checkWidth(uint64_t Value, unsigned Width) {
    if (Width && Width < 8 && Value >= (uint64_t(1) << (8 * Width)))
      report_fatal_error("DWARF relocation exceeds a fixed-width field");
  }

  void record(uint64_t Original) {
    if (Relocating) {
      Positions[Original] = Position;
      Moved |= Original != Position;
    }
  }

  uint64_t relocated(uint64_t Original) const {
    auto It = Positions.find(Original);
    if (It == Positions.end())
      report_fatal_error("DWARF relocation target is not a decoded DIE or unit");
    return It->second;
  }

  void onStartCompileUnit(Unit &CU) override {
    if (CU.Version < 2 || CU.Version > 5 ||
        (CU.Version == 5 && CU.Type != dwarf::DW_UT_compile &&
         CU.Type != dwarf::DW_UT_partial))
      report_fatal_error("DWARF layout does not support this unit header");
    record(CU.Offset);
    Current = &CU;
    Position += CU.Length.isDWARF64() ? 12 : 4;
    Start = Position;
    Position += 2 + offsetSize(CU) + 1 + (CU.Version >= 5 ? 1 : 0);
  }

  void onEndCompileUnit(Unit &CU) override {
    auto Length = Position - Start;
    Moved |= CU.Length.getLength() != Length;
    // Never change the unit's format implicitly: that changes the header width.
    if (CU.Length.isDWARF64())
      CU.Length.TotalLength64 = Length;
    else {
      if (Length >= 0xfffffff0)
        report_fatal_error("DWARF32 unit exceeds its length representation");
      CU.Length.TotalLength = Length;
    }
  }

  void onStartDIE(Unit &, Entry &DIE) override {
    record(DIE.Offset);
    Position += std::max(getULEB128Size(DIE.AbbrCode), DIE.AbbrSize);
  }

  bool independent(StringRef Bytes, const Unit &CU, unsigned Depth = 0) const {
    if (Depth > 64)
      return false;
    DataExtractor Data(Bytes, DebugInfo.IsLittleEndian, CU.AddrSize);
    uint64_t Offset = 0;
    while (Offset < Bytes.size()) {
      DWARFExpression::Operation Op;
      if (!Op.extract(Data, CU.Version, CU.AddrSize, Offset))
        return false;
      auto End = Op.getEndOffset();
      if (End <= Offset || End > Bytes.size())
        return false;
      switch (Op.getCode()) {
      case dwarf::DW_OP_call2:
      case dwarf::DW_OP_call4:
      case dwarf::DW_OP_call_ref:
        return false;
      case dwarf::DW_OP_convert:
        if (Op.getRawOperand(0))
          return false;
        break;
      case dwarf::DW_OP_entry_value:
      case dwarf::DW_OP_GNU_entry_value: {
        auto Size = Op.getRawOperand(0);
        if (Size > Bytes.size() - End ||
            !independent(Bytes.substr(End, Size), CU, Depth + 1))
          return false;
        End += Size;
        break;
      }
      default: break;
      }
      Offset = End;
    }
    return true;
  }

  void onForm(AttributeAbbrev &Abbrev, FormValue &Value) override {
    ByteSize = Value.ByteSize;
    Scalar = nullptr;
    auto Form = Abbrev.Form;
    if (Form == dwarf::DW_FORM_udata || Form == dwarf::DW_FORM_sdata ||
        Form == dwarf::DW_FORM_ref_udata)
      Scalar = &Value;
    if (!Collect || !Relocating)
      return;
    // Constant/discriminant blocks are data, not bytecode. Decode expressions
    // rather than searching raw bytes: a reference opcode can occur as data.
    if (!Value.BlockData.empty() &&
        Abbrev.Attribute != dwarf::DW_AT_const_value &&
        Abbrev.Attribute != dwarf::DW_AT_discr_list)
      Opaque |= !independent(StringRef((const char *)Value.BlockData.data(),
                                     Value.BlockData.size()), *Current);
    Opaque |= Form == dwarf::DW_FORM_indirect;
    unsigned Width = 0;
    bool Relative = true;
    switch (Form) {
    case dwarf::DW_FORM_ref_addr:
      Width = Current->Version == 2 ? Current->AddrSize : offsetSize(*Current);
      Relative = false;
      break;
    case dwarf::DW_FORM_ref1: Width = 1; break;
    case dwarf::DW_FORM_ref2: Width = 2; break;
    case dwarf::DW_FORM_ref4: Width = 4; break;
    case dwarf::DW_FORM_ref8: Width = 8; break;
    case dwarf::DW_FORM_ref_udata: break;
    default:
      if (Abbrev.Attribute == dwarf::DW_AT_high_pc) {
        switch (Form) {
        case dwarf::DW_FORM_data1: checkWidth(Value.Value, 1); break;
        case dwarf::DW_FORM_data2: checkWidth(Value.Value, 2); break;
        case dwarf::DW_FORM_data4: checkWidth(Value.Value, 4); break;
        default: break;
        }
      }
      return;
    }
    References.push_back({&Value,
                          uint64_t(Value.Value) + (Relative ? Current->Offset : 0),
                          Current->Offset, Width, Relative});
  }

  void leb(unsigned Width) {
    Width = std::max(Width, ByteSize);
    Position += Width;
    if (Scalar)
      Scalar->ByteSize = Width;
  }
  void onValue(uint8_t) override { Position += 1; }
  void onValue(uint16_t) override { Position += 2; }
  void onValue(uint32_t) override { Position += 4; }
  void onValue(uint64_t U, bool LEB = false) override {
    if (LEB) leb(getULEB128Size(U));
    else Position += 8;
  }
  void onValue(int64_t S, bool LEB = false) override {
    if (LEB) leb(getSLEB128Size(S));
    else Position += 8;
  }
  void onValue(StringRef S) override { Position += S.size() + 1; }
  void onValue(MemoryBufferRef M) override { Position += M.getBufferSize(); }

public:
  InfoLayout(Data &DI, bool Relocating) : Visitor(DI), Relocating(Relocating) {}

  bool run() {
    bool Grew;
    do {
      Position = 0;
      traverseDebugInfo();
      Collect = false;
      if (!Relocating)
        return Moved;
      Grew = false;
      for (auto &Ref : References) {
        auto Target = relocated(Ref.Target);
        auto Base = Ref.Relative ? relocated(Ref.Base) : 0;
        if (Target < Base)
          report_fatal_error("DWARF relative reference precedes its unit");
        auto Value = Target - Base;
        checkWidth(Value, Ref.Width);
        Ref.Value->Value = Value;
        Grew |= !Ref.Width && getULEB128Size(Value) > Ref.Value->ByteSize;
      }
    } while (Grew);

    if (Moved) {
      if (!DebugInfo.Locs.empty()) {
        if (DebugInfo.CompileUnits.empty())
          report_fatal_error("DWARF locations have no compilation unit");
        // The legacy location decoder uses the first CU's address size. Do not
        // claim a proof for mixed widths when a location list's owner is unknown.
        const auto &CU = DebugInfo.CompileUnits.front();
        bool Mixed = std::any_of(DebugInfo.CompileUnits.begin(),
                                 DebugInfo.CompileUnits.end(),
                                 [&](const Unit &Other) { return Other.AddrSize != CU.AddrSize; });
        for (const auto &Loc : DebugInfo.Locs) {
          if (Loc.Location.empty())
            continue;
          if (Mixed)
            report_fatal_error("DWARF mixed-width location relocation is unsupported");
          Opaque |= !independent(StringRef((const char *)Loc.Location.data(),
                                         Loc.Location.size()), CU);
        }
      }
      if (Opaque)
        report_fatal_error("DWARF relocation of expression references or unknown opcodes is unsupported");
      for (auto &Range : DebugInfo.ARanges) {
        if (Range.Length.isDWARF64())
          report_fatal_error("DWARF64 aranges relocation is unsupported");
        auto Offset = relocated(Range.CuOffset);
        checkWidth(Offset, 4);
        Range.CuOffset = Offset;
      }
    }
    return Moved;
  }
};
} // namespace

void llvm::DWARFYAML::ComputeDebugInfo(Data &DI) {
  InfoLayout(DI, false).run();
}

bool llvm::DWARFYAML::RelocateDebugInfo(Data &DI) {
  return InfoLayout(DI, true).run();
}
