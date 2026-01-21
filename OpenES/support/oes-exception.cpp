#include "oes-exception.h"


/** Constructor (C++ STL string, int, int).
 *  @param msg The error message
 */
OESException::OESException(std::string msg, int err_num) : error_message(std::move(msg)),
                                                           error_number(err_num) {
}

/** Destructor.
 *  Virtual to allow for subclassing.
 */
OESException::~OESException() noexcept = default;

/** Returns a pointer to the (constant) error description.
 *  @return A pointer to a const char*. The underlying memory
 *  is in possession of the Except object. Callers must
 *  not attempt to free the memory.
 */
const char *OESException::what() const noexcept {
    return error_message.c_str();
}

int OESException::getErrorNumber() const noexcept {
    return error_number;
}
