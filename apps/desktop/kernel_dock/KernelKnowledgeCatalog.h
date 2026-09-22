#pragma once

#include <QString>

#include <vector>

namespace ks::kernel_knowledge
{
    // Coverage purpose: describes the implementation chain status of the topic; historical enum values are retained for compatibility
    // with legacy language packs and future incremental topics. Currently, all 71 items are required by the validator to be Available.
    enum class Coverage : int
    {
        kAvailable = 0,
        kAvailableNeedsExplanation,
        kPartial,
        kPlanned
    };

    // CategoryDefinition: Describes the top-level category of the knowledge tree and its official Microsoft reference entry.
    // id is used only for constructing language pack keys; referenceUrl is a read-only external document link.
    struct CategoryDefinition
    {
        const char* id = nullptr;
        const char* referenceUrl = nullptr;
    };

    // TopicDefinition purpose: Define a topic's stable identity, capability coverage, and optional in-site observation entry.
    // A null routeId indicates that other Docks can only be entered manually via the path in the article, without faking cross-page jumps.
    struct TopicDefinition
    {
        const char* id = nullptr;
        const char* categoryId = nullptr;
        Coverage coverage = Coverage::kPlanned;
        const char* routeId = nullptr;
    };

    // categories: Returns top-level categories ordered by the chapters of 'The Second Plan'.
    // Returns a reference that remains stable for the process lifetime; the caller must not modify it.
    const std::vector<CategoryDefinition>& categories();

    // topics: Returns the complete list of 71 topics.
    // Returns a reference that remains stable throughout the process lifecycle; the order also serves as the navigation sequence for previous/next items.
    const std::vector<TopicDefinition>& topics();

    // categoryForTopic: Find the top-level category by topic categoryId.
    // Input topic is a topic within the catalog; returns the matching category, or nullptr if the catalog is corrupted.
    const CategoryDefinition* categoryForTopic(const TopicDefinition& topic);

    // categoryText: Read the localized title of the category.
    // Input category and field name; returns localized text, falling back to a stable key for diagnostics if the key is missing.
    QString categoryText(const CategoryDefinition& category, const char* field = "title");

    // topicText: Reads the localized title, summary, keywords, or body of a topic.
    // Takes topic and field name; returns localized text, or a stable key if the key is missing for diagnostics.
    QString topicText(const TopicDefinition& topic, const char* field);

    // coverageText: converts low-level capability coverage enums to localized labels.
    // Input: coverage; Return: short text suitable for tree columns and status badges.
    QString coverageText(Coverage coverage);
}
