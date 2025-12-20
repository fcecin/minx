#include <minx/blog.h>

#include <atomic>
#include <map>
#include <shared_mutex>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/container/small_vector.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>

#include <logkv/bytes.h>

namespace {
constexpr const char* kChannelAttrName = "Channel";
constexpr const char* kMessageAttrName = "Message";
constexpr const char* kSeverityAttrName = "Severity";
constexpr const char* kTimeStampAttrName = "TimeStamp";

struct BlogConfig {
  std::shared_mutex mutex;
  blog::severity_level global_level = blog::default_log_level;
  std::map<std::string, blog::severity_level> module_levels;
  std::atomic<bool> do_log{true};
  std::atomic<uint64_t> generation{1};
  std::atomic<bool> dim_log{false};
};

BlogConfig& get_config() {
  static BlogConfig cfg;
  return cfg;
}

struct FilterCache {
  uint64_t generation = 0;
  std::string module_name;
  int cached_level = 0;
};

static thread_local FilterCache t_cache;
} // namespace

bool blog_global_filter(boost::log::attribute_value_set const& set) {
  auto& cfg = get_config();
  if (!cfg.do_log.load(std::memory_order_relaxed))
    return false;
  auto severity_opt = set[kSeverityAttrName].extract<blog::severity_level>();
  if (!severity_opt)
    return true;
  int msg_level = severity_opt.get();
  uint64_t current_gen = cfg.generation.load(std::memory_order_acquire);
  auto channel_opt = set[kChannelAttrName].extract<std::string>();
  std::string current_module =
    channel_opt ? channel_opt.get() : blog::kDefaultModule;
  if (t_cache.generation == current_gen &&
      t_cache.module_name == current_module) {
    return msg_level >= t_cache.cached_level;
  }
  std::shared_lock<std::shared_mutex> lock(cfg.mutex);
  int target_level = cfg.global_level;
  auto it = cfg.module_levels.find(current_module);
  if (it != cfg.module_levels.end()) {
    target_level = it->second;
  }
  t_cache.generation = current_gen;
  t_cache.module_name = current_module;
  t_cache.cached_level = target_level;
  return msg_level >= target_level;
}

namespace blog {

void set_level(blog::severity_level level) {
  auto& cfg = get_config();
  std::lock_guard<std::shared_mutex> lock(cfg.mutex);
  cfg.global_level = level;
  for (auto it = cfg.module_levels.begin(); it != cfg.module_levels.end();) {
    if (it->second == blog::none) {
      ++it;
    } else {
      it = cfg.module_levels.erase(it);
    }
  }
  cfg.generation.fetch_add(1, std::memory_order_release);
}

void set_level(const std::string& module, blog::severity_level level) {
  auto& cfg = get_config();
  std::lock_guard<std::shared_mutex> lock(cfg.mutex);
  cfg.module_levels[module] = level;
  cfg.generation.fetch_add(1, std::memory_order_release);
}

void disable(const std::string& module) {
  auto& cfg = get_config();
  std::lock_guard<std::shared_mutex> lock(cfg.mutex);
  cfg.module_levels[module] = blog::none;
  cfg.generation.fetch_add(1, std::memory_order_release);
}

void enable(const std::string& module) {
  auto& cfg = get_config();
  std::lock_guard<std::shared_mutex> lock(cfg.mutex);
  cfg.module_levels.erase(module);
  cfg.generation.fetch_add(1, std::memory_order_release);
}

void disable() { disable(kDefaultModule); }

void enable() { enable(kDefaultModule); }

void turn_off() {
  auto& cfg = get_config();
  cfg.do_log.store(false, std::memory_order_relaxed);
}

void turn_on() {
  auto& cfg = get_config();
  cfg.do_log.store(true, std::memory_order_relaxed);
}

void dim(bool d) {
  auto& cfg = get_config();
  cfg.dim_log = d;
}

void format_hex(std::ostream& os, const void* ptr, size_t size) {
  if (ptr && size > 0) {
    const uint8_t* data = static_cast<const uint8_t*>(ptr);
    os << "[" << size << "]";
    const size_t max_sz = 1024;
    size_t count = (size > max_sz) ? max_sz : size;
    char buffer[max_sz * 2 + 1];
    char* p = buffer;
    for (size_t i = 0; i < count; ++i) {
      uint8_t byte = data[i];
      *p++ = logkv_detail::hexEncodeLookupUpper[byte >> 4];
      *p++ = logkv_detail::hexEncodeLookupUpper[byte & 0x0F];
    }
    os.write(buffer, p - buffer);
    if (count < size)
      os << "...";
  } else {
    os << "{}";
  }
}

void init() {
  static std::once_flag g_log_init_flag;
  std::call_once(g_log_init_flag, []() {
    boost::log::core::get()->set_filter(&blog_global_filter);
    boost::log::core::get()->add_global_attribute(
      kTimeStampAttrName, boost::log::attributes::local_clock());
    auto sink = boost::log::add_console_log(std::cout);
    sink->locked_backend()->auto_flush(true);
    auto formatter = [=](boost::log::record_view const& rec,
                         boost::log::formatting_ostream& strm) {
      constexpr const char* C_RESET = "\033[0m";
      constexpr const char* C_BOLD = "\033[1m";
      constexpr const char* C_TRACE_C = "\033[37m";
      constexpr const char* C_DEBUG_C = "\033[90m";
      constexpr const char* C_INFO_C = "\033[96m";
      constexpr const char* C_WARN_C = "\033[33m";
      constexpr const char* C_ERROR_C = "\033[91m";
      constexpr const char* C_FATAL_C = "\033[35m";
      constexpr const char* C_VAL_C = "\033[94m";
      constexpr const char* C_MODULE_C = "\033[93m";
      constexpr const char* MONO_C = "\033[90m";

      const char* REMOVE_COLOR = C_RESET;

      const char* RESET = C_RESET;
      const char* BOLD = C_BOLD;
      const char* TRACE_C = C_TRACE_C;
      const char* DEBUG_C = C_DEBUG_C;
      const char* INFO_C = C_INFO_C;
      const char* WARN_C = C_WARN_C;
      const char* ERROR_C = C_ERROR_C;
      const char* FATAL_C = C_FATAL_C;
      const char* VAL_C = C_VAL_C;
      const char* MODULE_C = C_MODULE_C;
      auto& cfg = get_config();
      if (cfg.dim_log) {
        RESET = MONO_C;
        BOLD = MONO_C;
        TRACE_C = MONO_C;
        DEBUG_C = MONO_C;
        INFO_C = MONO_C;
        WARN_C = MONO_C;
        ERROR_C = MONO_C;
        FATAL_C = MONO_C;
        VAL_C = MONO_C;
        MODULE_C = MONO_C;
      }

      auto severity = rec[boost::log::trivial::severity];
      const char* sev_color;
      if (severity) {
        switch (severity.get()) {
        case blog::trace:
          sev_color = TRACE_C;
          strm << TRACE_C << "TRC";
          break;
        case blog::debug:
          sev_color = DEBUG_C;
          strm << DEBUG_C << "DBG";
          break;
        case blog::info:
          sev_color = INFO_C;
          strm << INFO_C << "INF";
          break;
        case blog::warning:
          sev_color = WARN_C;
          strm << WARN_C << "WRN";
          break;
        case blog::error:
          sev_color = ERROR_C;
          strm << ERROR_C << "ERR";
          break;
        case blog::fatal:
          sev_color = FATAL_C;
          strm << FATAL_C << "FTL";
          break;
        default:
          sev_color = RESET;
          break;
        }
        strm << RESET << " ";
      }

      strm << boost::log::extract<boost::posix_time::ptime>(kTimeStampAttrName,
                                                            rec)
           << " ";

      auto channel = boost::log::extract<std::string>(kChannelAttrName, rec);
      std::string channelStr = channel ? channel.get() : blog::kDefaultModule;
      size_t channelLen =
        (channelStr != blog::kDefaultModule) ? channelStr.length() + 1 : 0;

      auto msgRef = boost::log::extract<std::string>(kMessageAttrName, rec);
      std::string msgStr = msgRef ? msgRef.get() : "";
      size_t msgLen = msgStr.length();

      size_t currentLen = channelLen + msgLen;

      constexpr int kBlockWidth = 50;
      int padding = (kBlockWidth > currentLen) ? (kBlockWidth - currentLen) : 0;
      if (channelLen > 0) {
        strm << MODULE_C << channelStr << RESET << " ";
      }
      strm << BOLD << msgStr << RESET;
      if (padding > 0) {
        strm << std::setw(padding) << "";
      }

      for (auto const& attr : rec.attribute_values()) {
        const std::string& name = attr.first.string();
        if (name == kSeverityAttrName || name == kMessageAttrName ||
            name == kFileAttrName || name == kLineAttrName ||
            name == kTimeStampAttrName || name == kChannelAttrName) {
          continue;
        }
        strm << " " << sev_color << name << RESET << "=" << VAL_C;
        if (auto val = boost::log::extract<std::string>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val =
                     boost::log::extract<const char*>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<std::vector<uint8_t>>(
                     attr.first, rec)) {
          strm << val.get();
        } else if (auto val =
                     boost::log::extract<std::vector<char>>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<uint64_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<uint32_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<uint16_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<uint8_t>(attr.first, rec)) {
          strm << static_cast<unsigned int>(val.get());
        } else if (auto val =
                     boost::log::extract<boost::asio::ip::udp::endpoint>(
                       attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<boost::asio::ip::address>(
                     attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<bool>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<int64_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<int32_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<int16_t>(attr.first, rec)) {
          strm << val.get();
        } else if (auto val = boost::log::extract<int8_t>(attr.first, rec)) {
          strm << static_cast<int>(val.get());
        } else {
          strm << "[?]";
        }
      }

      auto file = boost::log::extract<std::string>(kFileAttrName, rec);
      auto line = boost::log::extract<int>(kLineAttrName, rec);
      if (file && line) {
        strm << " " << sev_color << "file" << RESET << "=" << VAL_C
             << boost::filesystem::path(file.get()).filename().string() << ":"
             << line.get();
      }
      strm << REMOVE_COLOR;
    };
    sink->set_formatter(formatter);
  });
}

} // namespace blog

namespace std {
std::ostream& operator<<(std::ostream& os, const std::vector<uint8_t>& bin) {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
std::ostream& operator<<(std::ostream& os, const std::vector<char>& bin) {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, 32>& bin) {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, 8>& bin) {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
} // namespace std

namespace boost {
namespace container {
std::ostream& operator<<(std::ostream& os, const small_vector<char, 256>& v) {
  ::blog::format_hex(os, v.data(), v.size());
  return os;
}
} // namespace container
} // namespace boost

namespace {
struct BlogAutoInit {
  BlogAutoInit() { ::blog::init(); }
};

static BlogAutoInit g_blog_auto_init;
} // namespace