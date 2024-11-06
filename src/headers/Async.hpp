#ifndef PCAPTUREPP_ASYNC_HPP
#define PCAPTUREPP_ASYNC_HPP

#include "Includes.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>

namespace pcapturepp {
    template <typename T>
    class AsyncQueue {
        public:
            AsyncQueue() = default;
            
            void Push(const T& item) {
                std::lock_guard<std::mutex> lock(_mtx);
                _queue.push(item);
                _cv.notify_one();
            }

            void Clear() {
                std::queue<T> eq;
                std::swap(_queue, eq);
            }
            
            T Pop() {
                std::unique_lock<std::mutex> lock(_mtx);
                _cv.wait(lock, [this] { return !_queue.empty(); });
                T item = _queue.front();
                _queue.pop();
                return item;
            }

            bool Empty() const {
                return _queue.empty();
            }

        private:
            std::queue<T> _queue;
            std::mutex _mtx;
            std::condition_variable _cv;
    };
}

#endif // PCAPTURE_ASYNC_HPP