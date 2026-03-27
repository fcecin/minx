// Harness: spawns the startstop binary, monitors stdout for liveness,
// kills it if no output arrives within the timeout. Reports pass/fail.

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  // Default: 3 second timeout per heartbeat line
  int timeoutSec = 3;
  std::string subjectPath = "./startstop";

  if (argc > 1)
    subjectPath = argv[1];
  if (argc > 2)
    timeoutSec = std::stoi(argv[2]);

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    std::cerr << "pipe: " << std::strerror(errno) << std::endl;
    return 1;
  }

  pid_t child = fork();
  if (child < 0) {
    std::cerr << "fork: " << std::strerror(errno) << std::endl;
    return 1;
  }

  if (child == 0) {
    // Child: redirect stdout to pipe, exec subject
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    execl(subjectPath.c_str(), subjectPath.c_str(), nullptr);
    std::cerr << "exec: " << std::strerror(errno) << std::endl;
    _exit(127);
  }

  // Parent: read pipe with timeout
  close(pipefd[1]);

  char buf[4096];
  std::string lastLine;
  bool ok = false;

  while (true) {
    struct pollfd pfd = {pipefd[0], POLLIN, 0};
    int ret = poll(&pfd, 1, timeoutSec * 1000);

    if (ret < 0) {
      std::cerr << "poll: " << std::strerror(errno) << std::endl;
      break;
    }

    if (ret == 0) {
      // Timeout — no output
      std::cerr << "HANG DETECTED after " << timeoutSec
                << "s with no output. Last line: " << lastLine << std::endl;
      kill(child, SIGKILL);
      waitpid(child, nullptr, 0);
      close(pipefd[0]);
      return 1;
    }

    ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
    if (n <= 0) {
      // EOF — child closed stdout (exited)
      break;
    }
    buf[n] = '\0';

    // Extract last complete line for diagnostics
    std::string chunk(buf, n);
    auto pos = chunk.rfind('\n');
    if (pos != std::string::npos) {
      auto start = chunk.rfind('\n', pos - 1);
      lastLine =
        chunk.substr(start == std::string::npos ? 0 : start + 1,
                     pos - (start == std::string::npos ? 0 : start + 1));
    }

    if (chunk.find("OK") != std::string::npos) {
      ok = true;
    }
  }

  close(pipefd[0]);

  int status = 0;
  waitpid(child, &status, 0);

  if (ok && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    std::cout << "PASS" << std::endl;
    return 0;
  }

  if (WIFEXITED(status)) {
    std::cerr << "FAIL: subject exited with code " << WEXITSTATUS(status)
              << std::endl;
  } else if (WIFSIGNALED(status)) {
    std::cerr << "FAIL: subject killed by signal " << WTERMSIG(status)
              << std::endl;
  } else {
    std::cerr << "FAIL: no OK received" << std::endl;
  }
  return 1;
}
