#ifndef _MINXBLOG_H_
#define _MINXBLOG_H_

/**
 * Console logger for applications using Boost::Log's trivial logger.
 *
 * Simple use in any cpp file:
 *
 *   #include <minx/blog.h>
 *   int world = 100;
 *   LOGINFO << "Hello!" << VAR(world);
 *
 * To use with named module support in a cpp file:
 *
 *   #include <minx/blog.h>
 *   LOG_MODULE("mymod")
 *
 * To change the global logging severity level:
 *
 *   blog::set_level(blog::debug);
 *
 * To change the logging severity level per module:
 *
 *   blog::set_level("mymod", blog::trace);
 *
 * To add automatic instance name logging to a class:
 *
 *   class MyClass {
 *     std::string name_ = "Worker1";
 *     LOG_INSTANCE_NAME(name_);
 *   };
 *
 * See `src/minx.cpp` and `examples/hello/hello.cpp` for more usage examples.
 */

#include <cstdint>
#include <iterator>
#include <ostream>
#include <sstream>
#include <string>

#include <boost/container/small_vector.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>

namespace blog {
using severity_level = boost::log::trivial::severity_level;
constexpr auto trace = boost::log::trivial::trace;
constexpr auto debug = boost::log::trivial::debug;
constexpr auto info = boost::log::trivial::info;
constexpr auto warning = boost::log::trivial::warning;
constexpr auto error = boost::log::trivial::error;
constexpr auto fatal = boost::log::trivial::fatal;
constexpr auto none = static_cast<severity_level>(fatal + 1);
constexpr auto default_log_level = info;
constexpr const char* kDefaultModule = "";
constexpr const char* kFileAttrName = "File";
constexpr const char* kLineAttrName = "Line";
constexpr const char* kInstanceAttrName = "Inst";
} // namespace blog

namespace src = boost::log::sources;
namespace keywords = boost::log::keywords;

using logger_type =
  src::severity_channel_logger_mt<blog::severity_level, std::string>;

BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(my_logger, logger_type) {
  return logger_type(keywords::channel = blog::kDefaultModule);
}

namespace blog {
void format_hex(std::ostream& os, const void* ptr, size_t size);
} // namespace blog

namespace std {
template <typename T, std::size_t N>
inline auto operator<<(std::ostream& os, const std::array<T, N>& bin) ->
  typename std::enable_if_t<sizeof(T) == 1, std::ostream&> {
  ::blog::format_hex(os, bin.data(), N);
  return os;
}

template <typename T>
inline auto operator<<(std::ostream& os, const std::vector<T>& bin) ->
  typename std::enable_if_t<sizeof(T) == 1, std::ostream&> {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
} // namespace std

namespace boost::container {
template <typename T, std::size_t N>
inline auto operator<<(std::ostream& os, const small_vector<T, N>& bin) ->
  typename std::enable_if_t<sizeof(T) == 1, std::ostream&> {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}

template <typename T, std::size_t N>
inline auto operator<<(std::ostream& os, const static_vector<T, N>& bin) ->
  typename std::enable_if_t<sizeof(T) == 1, std::ostream&> {
  ::blog::format_hex(os, bin.data(), bin.size());
  return os;
}
} // namespace boost::container

namespace blog {
void set_level(blog::severity_level level);
void set_level(const std::string& module, blog::severity_level level);
void disable(const std::string& module);
void disable();
void enable(const std::string& module);
void enable();
void turn_off();
void turn_on();
void dim(bool d);
void init();

inline logger_type& get_logger() { return my_logger::get(); }

inline std::string to_str(const std::string& s) { return s; }
inline std::string to_str(const char* s) { return s; }
inline std::string to_str(char* s) { return s; }
template <typename T> std::string to_str(const T& value) {
  std::ostringstream oss;
  oss << value;
  return oss.str();
}

template <typename T> std::vector<uint8_t> to_vec(const T& container) {
  const uint8_t* ptr = reinterpret_cast<const uint8_t*>(std::data(container));
  size_t len = std::size(container);
  return std::vector<uint8_t>(ptr, ptr + len);
}
} // namespace blog

namespace blog_fallback {
static constexpr const char* resolve_log_module(long) {
  return ::blog::kDefaultModule;
}
static constexpr const char* _instanceName(long) { return ""; }
} // namespace blog_fallback

#define GET_MACRO(_1, _2, NAME, ...) NAME

#define LOG_MODULE_1(name)                                                     \
  static constexpr const char* resolve_log_module(int) { return name; }

#define LOG_MODULE_2(name, default_level)                                      \
  static constexpr const char* resolve_log_module(int) { return name; }        \
  static const bool _blog_module_init_hook =                                   \
    (::blog::set_level(name, default_level), true);

#define LOG_MODULE(...)                                                        \
  GET_MACRO(__VA_ARGS__, LOG_MODULE_2, LOG_MODULE_1)(__VA_ARGS__)

#define LOG_MODULE_DISABLED(name) LOG_MODULE(name, ::blog::none)

#define LOG_INSTANCE_NAME(name_expr)                                           \
  auto _instanceName(int) const { return (name_expr); }

#define MLOG_LEVEL(level)                                                      \
  BOOST_LOG_CHANNEL_SEV(::blog::get_logger(), ([]() {                          \
                          using namespace blog_fallback;                       \
                          return resolve_log_module(0);                        \
                        }()),                                                  \
                        level)                                                 \
    << ::boost::log::add_value(blog::kFileAttrName, __FILE__)                  \
    << ::boost::log::add_value(blog::kLineAttrName, __LINE__)                  \
    << ::boost::log::add_value(blog::kInstanceAttrName, [&]() {                \
         using namespace blog_fallback;                                        \
         return ::blog::to_str(_instanceName(0));                              \
       }())

#define LOGTRACE MLOG_LEVEL(::blog::trace)
#define LOGDEBUG MLOG_LEVEL(::blog::debug)
#define LOGINFO MLOG_LEVEL(::blog::info)
#define LOGWARNING MLOG_LEVEL(::blog::warning)
#define LOGERROR MLOG_LEVEL(::blog::error)
#define LOGFATAL MLOG_LEVEL(::blog::fatal)

// Supported types
#define VAR(variable) ::boost::log::add_value(#variable, variable)
#define VAL(key, value) ::boost::log::add_value(key, value)

// Any type that has operator<<(std::ostream&)
#define SVAR(variable)                                                         \
  ::boost::log::add_value(#variable, ::blog::to_str(variable))
#define SVAL(key, value) ::boost::log::add_value(key, ::blog::to_str(value))

#define LOG_TYPE(Type, ...)                                                    \
  inline std::ostream& operator<<(std::ostream& os, const Type& self) {        \
    return os << __VA_ARGS__;                                                  \
  }

// If variable is std::vector<B> where sizeof(B) == 1, can use VAR/VAL instead.
// If variable is std::array<uint8_t, 32>, can use VAR/VAL instead.
// If variable is std::array<uint8_t, 8>, can use VAR/VAL instead.
#define BVAR(variable)                                                         \
  ::boost::log::add_value(#variable, ::blog::to_vec(variable))
#define BVAL(key, variable)                                                    \
  ::boost::log::add_value(key, ::blog::to_vec(variable))

#define HEXU64(_EXPR_) std::format("{:#018x}", _EXPR_)

#endif
