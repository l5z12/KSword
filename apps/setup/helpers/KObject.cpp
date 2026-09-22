#include "KObject.h"

#include <algorithm>

KObject::KObject(KObject* parent)
    : objectName_(), parent_(nullptr), children_(), properties_() {
    setParent(parent);
}

KObject::KObject(const std::string& objectName, KObject* parent)
    : objectName_(objectName), parent_(nullptr), children_(), properties_() {
    setParent(parent);
}

KObject::~KObject() {
    if (parent_) {
        parent_->removeChildPointer(this);
        parent_ = nullptr;
    }
    deleteChildren();
}

std::string KObject::objectName() const {
    return objectName_;
}

void KObject::setObjectName(const std::string& objectName) {
    objectName_ = objectName;
}

KObject* KObject::parent() const {
    return parent_;
}

bool KObject::setParent(KObject* parent) {
    if (parent == parent_) {
        return true;
    }
    if (parent == this) {
        return false;
    }
    if (parent && parent->hasAncestor(this)) {
        return false;
    }

    if (parent_) {
        parent_->removeChildPointer(this);
    }
    parent_ = parent;
    if (parent_) {
        parent_->appendChildPointer(this);
    }
    return true;
}

std::vector<KObject*> KObject::children() const {
    return children_;
}

std::size_t KObject::childCount() const {
    return children_.size();
}

KObject* KObject::findChild(const std::string& objectName, bool recursive) const {
    for (std::vector<KObject*>::const_iterator it = children_.begin(); it != children_.end(); ++it) {
        KObject* child = *it;
        if (!child) {
            continue;
        }
        if (child->objectName() == objectName) {
            return child;
        }
        if (recursive) {
            KObject* nested = child->findChild(objectName, true);
            if (nested) {
                return nested;
            }
        }
    }
    return nullptr;
}

void KObject::deleteChildren() {
    std::vector<KObject*> ownedChildren = children_;
    children_.clear();

    for (std::vector<KObject*>::iterator it = ownedChildren.begin(); it != ownedChildren.end(); ++it) {
        KObject* child = *it;
        if (!child) {
            continue;
        }
        child->parent_ = nullptr;
        delete child;
    }
}

void KObject::setProperty(const std::string& name, const KVariant& value) {
    properties_[name] = value;
}

KVariant KObject::property(const std::string& name, const KVariant& defaultValue) const {
    std::map<std::string, KVariant>::const_iterator it = properties_.find(name);
    if (it == properties_.end()) {
        return defaultValue;
    }
    return it->second;
}

bool KObject::hasProperty(const std::string& name) const {
    return properties_.find(name) != properties_.end();
}

bool KObject::removeProperty(const std::string& name) {
    return properties_.erase(name) > 0;
}

std::vector<std::string> KObject::dynamicPropertyNames() const {
    std::vector<std::string> result;
    result.reserve(properties_.size());
    for (std::map<std::string, KVariant>::const_iterator it = properties_.begin(); it != properties_.end(); ++it) {
        result.push_back(it->first);
    }
    return result;
}

void KObject::appendChildPointer(KObject* child) {
    if (!child) {
        return;
    }
    if (std::find(children_.begin(), children_.end(), child) == children_.end()) {
        children_.push_back(child);
    }
}

void KObject::removeChildPointer(KObject* child) {
    children_.erase(std::remove(children_.begin(), children_.end(), child), children_.end());
}

bool KObject::hasAncestor(const KObject* possibleAncestor) const {
    const KObject* current = parent_;
    while (current) {
        if (current == possibleAncestor) {
            return true;
        }
        current = current->parent_;
    }
    return false;
}
