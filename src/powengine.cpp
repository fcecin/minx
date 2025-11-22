#include <minx/powengine.h>

RandomXVMReleaser::RandomXVMReleaser(PoWEngine* powEngine,
                                     std::shared_ptr<RandomXVM> rxvmSptr)
    : powEngine_(powEngine), rxvmSptr_(rxvmSptr) {
  if (!powEngine_) {
    throw std::runtime_error("RandomXVMReleaser cannot be constructed "
                             "from a PoWEngine* nullptr");
  }
  ++powEngine_->pendingReleasers_;
}

RandomXVMReleaser::~RandomXVMReleaser() {
  powEngine_->releaseVM(rxvmSptr_);
  --powEngine_->pendingReleasers_;
}
