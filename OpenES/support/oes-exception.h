#pragma once

#include <string>

class OESException : virtual public std::exception {
protected:
    std::string error_message; ///< Error message
    int error_number; ///< Error number

public:
    explicit OESException(std::string msg, int err_num = 0);

    /** Destructor.
     *  Virtual to allow for subclassing.
     */
    ~OESException() override;

    /** Returns a pointer to the (constant) error description.
     *  @return A pointer to a const char*. The underlying memory
     *  is in possession of the Except object. Callers must
     *  not attempt to free the memory.
     */
    const char *what() const noexcept override;

    /** Returns error number.
   *  @return #error_number
   */
    virtual int getErrorNumber() const noexcept;
};
