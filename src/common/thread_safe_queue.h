#pragma once

namespace lego {

namespace common {

template<class T>
struct QueueItem {
    T data;
    struct QueueItem* next;
};

template<class T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() : front_(new QueueItem<T>()), tail_(new QueueItem<T>()) {
        front_->next = nullptr;
        tail_->next = nullptr;
    }

    ~ThreadSafeQueue() {
        while (front_ != nullptr) {
            tail_ = front_->next;
            delete front_;
            front_ = tail_;
        }
    }

    void push(T e) {
        struct QueueItem<T>* p = new QueueItem<T>();
        p->next = 0;
        tail_->next = p;
        tail_->data = e;
        tail_ = p;
    }

    bool pop(T* e) {
        if (front_ == tail_) {
            return false;
        }


        auto p = front_;
        *e = p->data;
        front_ = p->next;
        delete p;
        return true;
    }

private:
    struct QueueItem<T>* volatile front_;
    struct QueueItem<T>* volatile tail_;

    DISALLOW_COPY_AND_ASSIGN(ThreadSafeQueue);
};

}  // namespace common

}  // namespace lego
