#include "KernelKnowledgeCatalog.h"

#include "../internationalization/LanguageManager.h"

#include <algorithm>

namespace ks::kernel_knowledge
{
    const std::vector<CategoryDefinition>& categories()
    {
        // Category references point only to public Microsoft documentation; private structure conclusions remain explicitly marked as PDB/DynData evidence in each article.
        static const std::vector<CategoryDefinition> kCatalog{
            { "execution_basics", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities" },
            { "driver_model", "https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/" },
            { "object_manager", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-kernel-objects" },
            { "cid_handles", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles" },
            { "process_thread", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager" },
            { "memory", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-for-drivers" },
            { "io_storage", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-i-o-manager" },
            { "registry", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls" },
            { "security", "https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist" },
            { "network_ipc_gui", "https://learn.microsoft.com/en-us/windows-hardware/drivers/network/" },
            { "hardware_power", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-plug-and-play" },
            { "observability", "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/wpp-software-tracing" }
        };
        return kCatalog;
    }

    const std::vector<TopicDefinition>& topics()
    {
        // 71 items correspond one-to-one in order with shared Research topic IDs and the 'Second Plan'.
        // Each item can collect versioned R0 runtime evidence, with the routeId redirecting to the corresponding business collection page.
        static const std::vector<TopicDefinition> kCatalog{
            { "execution_chain", "execution_basics", Coverage::kAvailable, "io_management" },
            { "address_spaces", "execution_basics", Coverage::kAvailable, "slat_iommu" },
            { "handles_references", "execution_basics", Coverage::kAvailable, "object_namespace" },
            { "status_codes", "execution_basics", Coverage::kAvailable, "io_management" },
            { "irql_context", "execution_basics", Coverage::kAvailable, "timer_dpc" },
            { "synchronization", "execution_basics", Coverage::kAvailable, "timer_dpc" },
            { "driver_lifecycle", "driver_model", Coverage::kAvailable, "object_namespace" },
            { "wdm_kmdf", "driver_model", Coverage::kAvailable, "io_management" },
            { "ioctl_chain", "driver_model", Coverage::kAvailable, "io_management" },
            { "debugging_dumps", "driver_model", Coverage::kAvailable, "kernel_audit" },
            { "object_manager", "object_manager", Coverage::kAvailable, "object_namespace" },
            { "object_directories", "object_manager", Coverage::kAvailable, "object_namespace" },
            { "symbolic_links", "object_manager", Coverage::kAvailable, "object_namespace" },
            { "object_header", "object_manager", Coverage::kAvailable, "object_namespace" },
            { "object_security", "object_manager", Coverage::kAvailable, "object_namespace" },
            { "psp_cid_table", "cid_handles", Coverage::kAvailable, "cid" },
            { "cid_object_relations", "cid_handles", Coverage::kAvailable, "cid" },
            { "handle_table_tablecode", "cid_handles", Coverage::kAvailable, "cid" },
            { "process_cross_view", "cid_handles", Coverage::kAvailable, "cid" },
            { "process_vs_cid_handles", "cid_handles", Coverage::kAvailable, "cid" },
            { "cross_view_visualization", "cid_handles", Coverage::kAvailable, "cid" },
            { "executive_thread_objects", "process_thread", Coverage::kAvailable, "cid" },
            { "process_lifecycle", "process_thread", Coverage::kAvailable, "cid" },
            { "scheduler", "process_thread", Coverage::kAvailable, "work_queue_threads" },
            { "dispatcher_objects", "process_thread", Coverage::kAvailable, "timer_dpc" },
            { "apc_dpc_work_items", "process_thread", Coverage::kAvailable, "timer_dpc" },
            { "process_attach", "process_thread", Coverage::kAvailable, "cid" },
            { "session_silo_pico", "process_thread", Coverage::kAvailable, "cid" },
            { "page_tables", "memory", Coverage::kAvailable, "slat_iommu" },
            { "page_fault_working_set", "memory", Coverage::kAvailable, "slat_iommu" },
            { "vad", "memory", Coverage::kAvailable, "object_namespace" },
            { "pfn_database", "memory", Coverage::kAvailable, "slat_iommu" },
            { "section_control_area", "memory", Coverage::kAvailable, "object_namespace" },
            { "mdl_dma", "memory", Coverage::kAvailable, "slat_iommu" },
            { "pool", "memory", Coverage::kAvailable, "text_integrity" },
            { "executable_memory_evidence", "memory", Coverage::kAvailable, "text_integrity" },
            { "irp_lifecycle", "io_storage", Coverage::kAvailable, "io_management" },
            { "driver_device_file_objects", "io_storage", Coverage::kAvailable, "object_namespace" },
            { "minifilter", "io_storage", Coverage::kAvailable, "kernel_audit" },
            { "cache_memory_manager", "io_storage", Coverage::kAvailable, "object_namespace" },
            { "filesystems", "io_storage", Coverage::kAvailable, "object_namespace" },
            { "storage_stack", "io_storage", Coverage::kAvailable, "object_namespace" },
            { "network_redirector", "io_storage", Coverage::kAvailable, "ipc" },
            { "registry_views", "registry", Coverage::kAvailable, "object_namespace" },
            { "configuration_manager", "registry", Coverage::kAvailable, "object_namespace" },
            { "registry_callbacks", "registry", Coverage::kAvailable, "kernel_audit" },
            { "registry_transactions", "registry", Coverage::kAvailable, "kernel_audit" },
            { "token", "security", Coverage::kAvailable, "cid" },
            { "authentication_stack", "security", Coverage::kAvailable, "vbs" },
            { "protected_process", "security", Coverage::kAvailable, "cid" },
            { "code_integrity", "security", Coverage::kAvailable, "text_integrity" },
            { "vbs_hvci", "security", Coverage::kAvailable, "vbs" },
            { "patchguard", "security", Coverage::kAvailable, "text_integrity" },
            { "network_stack", "network_ipc_gui", Coverage::kAvailable, "ipc" },
            { "wfp_ndis", "network_ipc_gui", Coverage::kAvailable, "kernel_audit" },
            { "afd_nsi", "network_ipc_gui", Coverage::kAvailable, "ipc" },
            { "alpc", "network_ipc_gui", Coverage::kAvailable, "ipc" },
            { "ipc", "network_ipc_gui", Coverage::kAvailable, "ipc" },
            { "win32k_gui", "network_ipc_gui", Coverage::kAvailable, "kernel_audit" },
            { "pnp", "hardware_power", Coverage::kAvailable, "object_namespace" },
            { "device_stack", "hardware_power", Coverage::kAvailable, "object_namespace" },
            { "acpi_pci", "hardware_power", Coverage::kAvailable, "slat_iommu" },
            { "usb_hid", "hardware_power", Coverage::kAvailable, "object_namespace" },
            { "gpu_tdr", "hardware_power", Coverage::kAvailable, "object_namespace" },
            { "power_management", "hardware_power", Coverage::kAvailable, "slat_iommu" },
            { "callbacks", "observability", Coverage::kAvailable, "kernel_audit" },
            { "external_callbacks", "observability", Coverage::kAvailable, "kernel_audit" },
            { "hook_evidence", "observability", Coverage::kAvailable, "kernel_audit" },
            { "cpu_control_state", "observability", Coverage::kAvailable, "io_management" },
            { "tracing", "observability", Coverage::kAvailable, "kernel_audit" },
            { "evidence_timeline", "observability", Coverage::kAvailable, "cid" }
        };
        return kCatalog;
    }

    const CategoryDefinition* categoryForTopic(const TopicDefinition& topic)
    {
        const auto& catalog = categories();
        const auto kMatch = std::find_if(
            catalog.cbegin(),
            catalog.cend(),
            [&topic](const CategoryDefinition& category)
            {
                return QString::fromLatin1(category.id) == QString::fromLatin1(topic.categoryId);
            });
        return kMatch != catalog.cend() ? &(*kMatch) : nullptr;
    }

    QString categoryText(const CategoryDefinition& category, const char* field)
    {
        const QString kKey = QStringLiteral("kernel.knowledge.category.%1.%2")
            .arg(QString::fromLatin1(category.id), QString::fromLatin1(field));
        return ks::i18n::text(kKey);
    }

    QString topicText(const TopicDefinition& topic, const char* field)
    {
        const QString kKey = QStringLiteral("kernel.knowledge.topic.%1.%2")
            .arg(QString::fromLatin1(topic.id), QString::fromLatin1(field));
        return ks::i18n::text(kKey);
    }

    QString coverageText(const Coverage coverage)
    {
        const char* keySuffix = "planned";
        switch (coverage)
        {
        case Coverage::kAvailable:
            keySuffix = "available";
            break;
        case Coverage::kAvailableNeedsExplanation:
            keySuffix = "needs_explanation";
            break;
        case Coverage::kPartial:
            keySuffix = "partial";
            break;
        case Coverage::kPlanned:
            keySuffix = "planned";
            break;
        }

        const QString kKey = QStringLiteral("kernel.knowledge.coverage.%1")
            .arg(QString::fromLatin1(keySuffix));
        return ks::i18n::text(kKey);
    }
}
