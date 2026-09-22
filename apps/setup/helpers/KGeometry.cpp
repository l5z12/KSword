#include "KGeometry.h"

#include <algorithm>

KPoint::KPoint()
    : x_(0), y_(0) {
}

KPoint::KPoint(int x, int y)
    : x_(x), y_(y) {
}

int KPoint::x() const {
    return x_;
}

int KPoint::y() const {
    return y_;
}

void KPoint::setX(int x) {
    x_ = x;
}

void KPoint::setY(int y) {
    y_ = y;
}

KPoint KPoint::translated(int dx, int dy) const {
    return KPoint(x_ + dx, y_ + dy);
}

bool KPoint::operator==(const KPoint& other) const {
    return x_ == other.x_ && y_ == other.y_;
}

bool KPoint::operator!=(const KPoint& other) const {
    return !(*this == other);
}

KSize::KSize()
    : width_(0), height_(0) {
}

KSize::KSize(int width, int height)
    : width_(width), height_(height) {
}

int KSize::width() const {
    return width_;
}

int KSize::height() const {
    return height_;
}

void KSize::setWidth(int width) {
    width_ = width;
}

void KSize::setHeight(int height) {
    height_ = height;
}

bool KSize::isEmpty() const {
    return width_ <= 0 || height_ <= 0;
}

bool KSize::isValid() const {
    return width_ >= 0 && height_ >= 0;
}

KSize KSize::expandedTo(const KSize& other) const {
    return KSize(std::max(width_, other.width_), std::max(height_, other.height_));
}

KSize KSize::boundedTo(const KSize& other) const {
    return KSize(std::min(width_, other.width_), std::min(height_, other.height_));
}

bool KSize::operator==(const KSize& other) const {
    return width_ == other.width_ && height_ == other.height_;
}

bool KSize::operator!=(const KSize& other) const {
    return !(*this == other);
}

KRect::KRect()
    : x_(0), y_(0), width_(0), height_(0) {
}

KRect::KRect(int x, int y, int width, int height)
    : x_(x), y_(y), width_(width), height_(height) {
}

KRect::KRect(const KPoint& topLeft, const KSize& size)
    : x_(topLeft.x()), y_(topLeft.y()), width_(size.width()), height_(size.height()) {
}

int KRect::x() const {
    return x_;
}

int KRect::y() const {
    return y_;
}

int KRect::width() const {
    return width_;
}

int KRect::height() const {
    return height_;
}

int KRect::left() const {
    return x_;
}

int KRect::top() const {
    return y_;
}

int KRect::right() const {
    return x_ + width_;
}

int KRect::bottom() const {
    return y_ + height_;
}

KPoint KRect::topLeft() const {
    return KPoint(x_, y_);
}

KSize KRect::size() const {
    return KSize(width_, height_);
}

void KRect::setX(int x) {
    x_ = x;
}

void KRect::setY(int y) {
    y_ = y;
}

void KRect::setWidth(int width) {
    width_ = width;
}

void KRect::setHeight(int height) {
    height_ = height;
}

void KRect::setTopLeft(const KPoint& point) {
    x_ = point.x();
    y_ = point.y();
}

void KRect::setSize(const KSize& size) {
    width_ = size.width();
    height_ = size.height();
}

bool KRect::isEmpty() const {
    return width_ <= 0 || height_ <= 0;
}

bool KRect::contains(const KPoint& point) const {
    return contains(point.x(), point.y());
}

bool KRect::contains(int x, int y) const {
    return !isEmpty() && x >= left() && x < right() && y >= top() && y < bottom();
}

KRect KRect::translated(int dx, int dy) const {
    return KRect(x_ + dx, y_ + dy, width_, height_);
}

bool KRect::intersects(const KRect& other) const {
    if (isEmpty() || other.isEmpty()) {
        return false;
    }
    return left() < other.right() && other.left() < right() && top() < other.bottom() && other.top() < bottom();
}

KRect KRect::intersected(const KRect& other) const {
    if (!intersects(other)) {
        return KRect();
    }

    const int kNewLeft = std::max(left(), other.left());
    const int kNewTop = std::max(top(), other.top());
    const int kNewRight = std::min(right(), other.right());
    const int kNewBottom = std::min(bottom(), other.bottom());
    return KRect(kNewLeft, kNewTop, kNewRight - kNewLeft, kNewBottom - kNewTop);
}

KRect KRect::united(const KRect& other) const {
    if (isEmpty()) {
        return other;
    }
    if (other.isEmpty()) {
        return *this;
    }

    const int kNewLeft = std::min(left(), other.left());
    const int kNewTop = std::min(top(), other.top());
    const int kNewRight = std::max(right(), other.right());
    const int kNewBottom = std::max(bottom(), other.bottom());
    return KRect(kNewLeft, kNewTop, kNewRight - kNewLeft, kNewBottom - kNewTop);
}

bool KRect::operator==(const KRect& other) const {
    return x_ == other.x_ && y_ == other.y_ && width_ == other.width_ && height_ == other.height_;
}

bool KRect::operator!=(const KRect& other) const {
    return !(*this == other);
}
