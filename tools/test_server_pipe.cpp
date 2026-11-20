// plausibleServerPipe gates every read of a CServerPipe that GetServerPipe returns: an object
// that does not lie whole in readable memory is rejected without being touched (each of those
// cases faults if the gate reads it), and a readable one only with a pid Linux can hand out.
#include "sdk/CSteamEngine.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sys/mman.h>
#include <unistd.h>

static int failures = 0;

static void expect(bool ok, const char* text)
{
	std::printf("%s: %s\n", ok ? "ok" : "FAIL", text);
	if (!ok)
		++failures;
}

static CServerPipe* at(std::uintptr_t address)
{
	return reinterpret_cast<CServerPipe*>(address);
}

int main()
{
	const std::size_t page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
	// [readable page][PROT_NONE page][unmapped page]
	auto* const base = static_cast<unsigned char*>(
		mmap(nullptr, 3 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	if (base == MAP_FAILED || mprotect(base + page, page, PROT_NONE) != 0
	    || munmap(base + 2 * page, page) != 0)
	{
		std::perror("mmap");
		return 2;
	}
	const auto self = static_cast<std::int32_t>(getpid());

	CServerPipe* const pipe = at(reinterpret_cast<std::uintptr_t>(base + 64));
	pipe->pid = self;
	expect(plausibleServerPipe(pipe), "a readable pipe holding this process's pid is accepted");
	pipe->pid = (1 << 22) - 1;
	expect(plausibleServerPipe(pipe), "the highest pid Linux hands out is accepted");
	pipe->pid = 0;
	expect(!plausibleServerPipe(pipe), "pid 0 is rejected");
	pipe->pid = -1;
	expect(!plausibleServerPipe(pipe), "a negative pid is rejected");
	pipe->pid = 1 << 22;
	expect(!plausibleServerPipe(pipe), "a pid at PID_MAX_LIMIT is rejected");

	CServerPipe* const last = at(reinterpret_cast<std::uintptr_t>(base + page - sizeof(CServerPipe)));
	last->pid = self;
	expect(plausibleServerPipe(last), "a pipe ending exactly at the end of its mapping is accepted");

	expect(!plausibleServerPipe(nullptr), "null is rejected");
	expect(!plausibleServerPipe(at(0x28)), "a small integer read as a pointer is rejected");
	expect(!plausibleServerPipe(at(~std::uintptr_t{0})), "the all-ones sentinel is rejected");
	if constexpr (sizeof(void*) == 8)
	{
		expect(!plausibleServerPipe(at(0x0000800000000000ull)),
		       "the first non-canonical address is rejected");
		expect(!plausibleServerPipe(at(0xFFFF800000000000ull)), "a kernel-half address is rejected");
	}
	expect(!plausibleServerPipe(at(reinterpret_cast<std::uintptr_t>(base + page + 64))),
	       "a pipe in a PROT_NONE mapping is rejected");
	expect(!plausibleServerPipe(at(reinterpret_cast<std::uintptr_t>(base + 2 * page + 64))),
	       "a pipe in an unmapped page is rejected");

	// Its pid is readable and valid, but the last four bytes lie in the PROT_NONE page.
	CServerPipe* const straddling =
		at(reinterpret_cast<std::uintptr_t>(base + page - sizeof(CServerPipe) + 4));
	straddling->pid = self;
	expect(!plausibleServerPipe(straddling), "a pipe running past the end of its mapping is rejected");

	munmap(base, 2 * page);
	return failures == 0 ? 0 : 1;
}
